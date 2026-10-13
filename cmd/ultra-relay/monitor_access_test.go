package main

import (
	"bytes"
	"encoding/json"
	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
	"github.com/xtls/xray-core/core"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMonitorRestrictionsSurviveAutonomousSnapshot(t *testing.T) {
	r, _, p := runtimeFixture(t)
	p.Version = 2
	p.Users[0].ServiceTargets = []string{"https://probe.example/health"}
	raw, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	saved := runtimestate.Snapshot{ConfirmedAt: r.now(), Payload: raw}
	decoded, e := decodeRuntimeSnapshot(saved, p.Fingerprint, r.now().Add(time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	users := decoded.users()
	if len(users) != 1 || len(users[0].ServiceTargets) != 1 || users[0].ServiceTargets[0] != "https://probe.example/health" {
		t.Fatal("service restriction lost")
	}
}
func TestMonitorOutputPrivateAtomicAndRejectsLinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "probe.json")
	if e := privateMonitorWrite(path, []byte("first")); e != nil {
		t.Fatal(e)
	}
	if e := privateMonitorWrite(path, []byte("second")); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(path)
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("unsafe mode", e)
	}
	link := filepath.Join(dir, "link")
	if e = os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if e = privateMonitorWrite(link, []byte("bad")); e == nil {
		t.Fatal("followed link")
	}
	data, e := os.ReadFile(path)
	if e != nil || string(data) != "second" {
		t.Fatal("target altered", e)
	}
}

func TestMonitorProfileIsValidAndDoesNotDownloadProbeBody(t *testing.T) {
	spec := &config.Spec{Role: config.RoleBridge, DevMode: true, PublicHost: "127.0.0.1", VLESSPort: 24443}
	u := auth.User{UUID: "11111111-2222-3333-4444-555555555555", Kind: "vless", IsActive: true}
	raw, e := monitorProfile(spec, u, []string{"https://probe.example/health"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = core.LoadConfig("json", bytes.NewReader(raw)); e != nil {
		t.Fatal(e)
	}
	var profile map[string]any
	if e = json.Unmarshal(raw, &profile); e != nil {
		t.Fatal(e)
	}
	ping := profile["burstObservatory"].(map[string]any)["pingConfig"].(map[string]any)
	if ping["httpMethod"] != "HEAD" || ping["interval"] != "30s" || ping["destination"] != "https://probe.example/health" {
		t.Fatal(ping)
	}
}
