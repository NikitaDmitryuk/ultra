package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

const maxSubscriptionKeyringBytes = 1 << 20

var subscriptionKeyID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func prepareUpgradeSubscriptionStage(p *installplan.InstallPlan, directory string, generation int) (string, func() error, error) {
	if p == nil || p.SourceValues == nil || strings.TrimSpace(p.SourceValues["ULTRA_SUBSCRIPTION_ENCRYPTION_KEY_FILE"]) == "" {
		return "", nil, nil
	}
	if generation < 1 {
		return "", nil, errors.New("invalid subscription keyring")
	}
	source := p.SourceValues["ULTRA_SUBSCRIPTION_ENCRYPTION_KEY_FILE"]
	if !filepath.IsAbs(source) || filepath.Clean(source) != source {
		return "", nil, errors.New("invalid subscription keyring")
	}
	raw, err := readSubscriptionKeyringSource(source)
	if err != nil || validateSubscriptionKeyring(raw) != nil {
		return "", nil, errors.New("invalid subscription keyring")
	}
	stageDir := upgradeDependentStageDirectory(directory, "subscription-keys", generation)
	if err = ensurePrivateBootstrapDirectory(stageDir); err != nil {
		return "", nil, errors.New("subscription keyring staging failed")
	}
	fingerprintPath := filepath.Join(stageDir, "source.sha256")
	fingerprint := []byte(fmt.Sprintf("%x\n", sha256.Sum256(raw)))
	if _, statErr := os.Lstat(fingerprintPath); statErr == nil {
		previous, readErr := readSubscriptionKeyringSource(fingerprintPath)
		if readErr != nil || !bytes.Equal(previous, fingerprint) {
			return "", nil, errors.New("subscription keyring changed during operation")
		}
	} else if !os.IsNotExist(statErr) {
		return "", nil, errors.New("subscription keyring staging failed")
	} else if err = writeSubscriptionKeyringStage(fingerprintPath, fingerprint); err != nil {
		// Another retry may have created the immutable marker concurrently.
		previous, readErr := readSubscriptionKeyringSource(fingerprintPath)
		if readErr != nil || !bytes.Equal(previous, fingerprint) {
			return "", nil, errors.New("subscription keyring changed during operation")
		}
	}
	stage := filepath.Join(stageDir, "keyring.json")
	if _, statErr := os.Lstat(stage); statErr == nil {
		existing, readErr := readSubscriptionKeyringSource(stage)
		if readErr != nil || !bytes.Equal(existing, raw) {
			return "", nil, errors.New("subscription keyring changed during operation")
		}
	} else if !os.IsNotExist(statErr) {
		return "", nil, errors.New("subscription keyring staging failed")
	} else if err = writeSubscriptionKeyringStage(stage, raw); err != nil {
		return "", nil, errors.New("subscription keyring staging failed")
	}
	latest, err := readSubscriptionKeyringSource(source)
	if err != nil || !bytes.Equal(latest, raw) {
		return "", nil, errors.New("subscription keyring changed during operation")
	}
	return stage, func() error {
		if err := os.Remove(stage); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}, nil
}

func writeSubscriptionKeyringStage(path string, raw []byte) error {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "subscription-keyring-stage")
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return closeErr
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	err = dir.Sync()
	closeErr = dir.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func readSubscriptionKeyringSource(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 {
		return nil, errors.New("invalid source")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "subscription-keyring")
	defer f.Close() //nolint:errcheck
	var st syscall.Stat_t
	if err = syscall.Fstat(fd, &st); err != nil || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) ||
		st.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		st.Mode&0777 != 0600 ||
		st.Size < 1 ||
		st.Size > maxSubscriptionKeyringBytes {
		return nil, errors.New("invalid source")
	}
	var lstat syscall.Stat_t
	if err = syscall.Lstat(path, &lstat); err != nil || st.Dev != lstat.Dev || st.Ino != lstat.Ino {
		return nil, errors.New("source changed")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxSubscriptionKeyringBytes+1))
	if err != nil || len(raw) > maxSubscriptionKeyringBytes || int64(len(raw)) != st.Size {
		return nil, errors.New("invalid source")
	}
	return raw, nil
}

func validateSubscriptionKeyring(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return errors.New("invalid")
	}
	seenTop := map[string]bool{}
	active := ""
	keys := map[string]string{}
	for dec.More() {
		nameTok, e := dec.Token()
		if e != nil {
			return errors.New("invalid")
		}
		name, ok := nameTok.(string)
		if !ok || seenTop[name] {
			return errors.New("invalid")
		}
		seenTop[name] = true
		switch name {
		case "active":
			if dec.Decode(&active) != nil {
				return errors.New("invalid")
			}
		case "keys":
			kt, e := dec.Token()
			if e != nil || kt != json.Delim('{') {
				return errors.New("invalid")
			}
			for dec.More() {
				idTok, e := dec.Token()
				if e != nil {
					return errors.New("invalid")
				}
				id, ok := idTok.(string)
				if !ok || !subscriptionKeyID.MatchString(id) {
					return errors.New("invalid")
				}
				if _, exists := keys[id]; exists {
					return errors.New("invalid")
				}
				var encoded string
				if dec.Decode(&encoded) != nil {
					return errors.New("invalid")
				}
				key, e := base64.StdEncoding.DecodeString(encoded)
				if e != nil || len(key) != 32 {
					return errors.New("invalid")
				}
				keys[id] = encoded
			}
			if _, e = dec.Token(); e != nil {
				return errors.New("invalid")
			}
		default:
			return errors.New("invalid")
		}
	}
	if _, err = dec.Token(); err != nil || len(seenTop) != 2 || active == "" || !subscriptionKeyID.MatchString(active) || len(keys) == 0 {
		return errors.New("invalid")
	}
	if _, ok := keys[active]; !ok {
		return errors.New("invalid")
	}
	var trailing any
	if err = dec.Decode(&trailing); err != io.EOF {
		return errors.New("invalid")
	}
	return nil
}
