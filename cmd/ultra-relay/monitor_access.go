package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/db"
)

func privateMonitorWrite(path string, data []byte) error {
	if !filepath.IsAbs(path) {
		return errors.New("absolute private output path required")
	}
	if info, e := os.Lstat(path); e == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
		return errors.New("unsafe monitor output")
	}
	if old, e := os.ReadFile(path); e == nil && bytes.Equal(old, data) {
		return nil
	}
	parent := filepath.Dir(path)
	if info, e := os.Lstat(parent); e == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
		return errors.New("unsafe monitor parent")
	}
	if e := os.MkdirAll(parent, 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(parent, ".monitor-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name()) //nolint:errcheck
	if _, e = f.Write(data); e != nil {
		_ = f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		_ = f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return e
	}
	dir, e := os.Open(parent)
	if e != nil {
		return e
	}
	defer dir.Close() //nolint:errcheck
	return dir.Sync()
}
func ensureMonitorAccess(ctx context.Context, spec *config.Spec, output, chatOutput, targetsCSV string, initialAdmin int64) error {
	if spec.Role != config.RoleBridge || spec.Database == nil || spec.Database.DSN == "" || output == "" {
		return errors.New("monitor requires bridge database and private profile output")
	}
	database, e := db.Open(ctx, spec.Database.DSN)
	if e != nil {
		return errors.New("monitor database unavailable")
	}
	defer database.Close()
	if initialAdmin != 0 {
		if e = db.NewUserRepo(database).EnsureInitialMonitorAdmin(ctx, initialAdmin); e != nil {
			return e
		}
	}
	targets := strings.Split(targetsCSV, ",")
	for i := range targets {
		targets[i] = strings.TrimSpace(targets[i])
	}
	user, e := db.NewUserRepo(database).EnsureMonitorAccess(ctx, targets)
	if e != nil {
		return e
	}
	raw, e := monitorProfile(spec, user, targets)
	if e != nil {
		return e
	}
	if e = privateMonitorWrite(output, raw); e != nil {
		return e
	}
	if chatOutput != "" {
		admin, err := db.NewBotAdminRepo(database).FirstAdmin(ctx)
		if err != nil {
			return errors.New("monitor admin recipient unavailable")
		}
		if e = privateMonitorWrite(chatOutput, []byte(strconv.FormatInt(admin.TelegramID, 10)+"\n")); e != nil {
			return e
		}
	}
	_, e = db.NewQuotaRepo(database).Recalculate(ctx, time.Now().UTC())
	if e != nil {
		return e
	}
	available, e := db.NewQuotaRepo(database).HasAvailableExit(ctx, user.UUID)
	if e != nil {
		return e
	}
	fmt.Printf("{\"monitor_access\":\"ready\",\"quota_available\":%t}\n", available)
	return nil
}

func monitorProfile(spec *config.Spec, user auth.User, targets []string) ([]byte, error) {
	if len(targets) == 0 {
		return nil, errors.New("monitor targets required")
	}
	profile, e := config.BuildHappProfile(spec, user, "Infrastructure monitor")
	if e != nil {
		return nil, errors.New("monitor profile unavailable")
	}
	// Probe exactly the provisioned HTTPS target, never the generic Happ probe URL.
	observer := profile["burstObservatory"].(map[string]any)
	observer["pingConfig"].(map[string]any)["destination"] = targets[0]
	observer["pingConfig"].(map[string]any)["interval"] = "30s"
	observer["pingConfig"].(map[string]any)["httpMethod"] = "HEAD"
	raw, e := json.Marshal(profile)
	if e != nil {
		return nil, e
	}
	return raw, nil
}
