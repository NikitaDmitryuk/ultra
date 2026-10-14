package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func validMigrationOptions() migrationOptions {
	return migrationOptions{Phase: "preflight", Config: "example.config", Directory: "private-job", SourceHost: "192.0.2.10", TargetHost: "192.0.2.20", SourceUser: "root", TargetUser: "root"}
}
func TestMigrationOptionsRejectBeforeReadingConfiguration(t *testing.T) {
	for _, mutate := range []func(*migrationOptions){
		func(o *migrationOptions) { o.SourceHost = o.TargetHost },
		func(o *migrationOptions) { o.TargetHost = "-oProxyCommand=bad" },
		func(o *migrationOptions) { o.Phase = "freeze"; o.Confirm = "FREEZE" },
		func(o *migrationOptions) {
			o.Phase = "activate"
			o.Confirm = "ACTIVATE"
			o.ProbeURL = "https://example.com/ip"
			o.ExpectedIP = "192.0.2.30"
		},
		func(o *migrationOptions) { o.Phase = "rollback" },
		func(o *migrationOptions) { o.ProbeURL = "https://user:pass@example.com/ip" },
		func(o *migrationOptions) { o.ProbeURL = "http://example.com/ip" },
	} {
		o := validMigrationOptions()
		mutate(&o)
		if validateMigrationOptions(o) == nil {
			t.Fatalf("unsafe options accepted: %+v", o)
		}
	}
	o := validMigrationOptions()
	o.Phase = "activate"
	o.Confirm = "ACTIVATE"
	o.NetworkReady = true
	o.ProbeURL = "https://example.com/ip"
	o.ExpectedIP = "192.0.2.30"
	if err := validateMigrationOptions(o); err != nil {
		t.Fatal(err)
	}
}
func TestMigrationMachineCapacityAndIdentity(t *testing.T) {
	source := migrationMachine{MachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Architecture: "x86_64", OS: "ubuntu", OSVersion: "24.04", CPUCount: 2, MemoryBytes: 1 << 30, DatabaseBytes: 1 << 20, StateBytes: 1 << 20, PGMajor: 16, PGUnit: "postgresql@16-main.service"}
	target := source
	target.MachineID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	target.PythonABI = "3.12"
	target.FreeBytes = 1 << 30
	if err := validateMigrationMachines(source, target); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*migrationMachine){
		func(m *migrationMachine) { m.MachineID = source.MachineID },
		func(m *migrationMachine) { m.Architecture = "aarch64" },
		func(m *migrationMachine) { m.PGMajor = 15 },
		func(m *migrationMachine) { m.PythonABI = "3.11" },
		func(m *migrationMachine) { m.CPUCount = 1 },
		func(m *migrationMachine) { m.MemoryBytes = 0 },
		func(m *migrationMachine) { m.FreeBytes = 0 },
	} {
		bad := target
		mutate(&bad)
		if validateMigrationMachines(source, bad) == nil {
			t.Fatalf("unsafe target accepted: %+v", bad)
		}
	}
	source.DatabaseBytes = 1 << 62
	if validateMigrationMachines(source, target) == nil {
		t.Fatal("overflow accepted")
	}
}
func TestMigrationCiphertextIsImmutableAndPrivate(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.age")
	destination := filepath.Join(dir, "copy.age")
	data := []byte("authenticated ciphertext")
	sum := sha256.Sum256(data)
	expected := hex.EncodeToString(sum[:])
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := copyMigrationCipher(source, destination, expected); err != nil {
			t.Fatal(err)
		}
	}
	stat, err := os.Stat(destination)
	if err != nil || stat.Mode().Perm() != 0600 {
		t.Fatalf("mode: %v %v", stat, err)
	}
	if err = os.WriteFile(destination, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if copyMigrationCipher(source, destination, expected) == nil {
		t.Fatal("immutable generation replaced")
	}
	if err = os.Remove(destination); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(source, destination); err != nil {
		t.Fatal(err)
	}
	if copyMigrationCipher(source, destination, expected) == nil {
		t.Fatal("symlink accepted")
	}
}

func TestMigrationFreezeRecoveryRequiresConfirmedTargetStop(t *testing.T) {
	cause := errors.New("capture_failed")
	for _, failAt := range []string{"stop-target", "rollback-source", ""} {
		var calls []string
		state := migrationState{Phase: "freezing"}
		variables := map[string]any{}
		result := recoverMigrationFreeze(cause, &state, filepath.Join(t.TempDir(), "state.json"), variables, func(phase string) error {
			calls = append(calls, phase)
			if phase == failAt {
				return errors.New("failed")
			}
			return nil
		})
		if !errors.Is(result, cause) {
			t.Fatal("original failure lost")
		}
		if failAt == "stop-target" && len(calls) != 1 {
			t.Fatal("source restarted without confirmed target fencing")
		}
		if failAt == "" && state.Phase != "rolled_back" {
			t.Fatal("completed recovery not recorded")
		}
		if failAt != "" && state.Phase == "rolled_back" {
			t.Fatal("failed recovery reported success")
		}
	}
}

func TestMigrationPayloadMustPassBeforeBotAndFailureFencesTarget(t *testing.T) {
	for _, failAt := range []string{"peer_reseed", "activate", "payload", "migration-bot", ""} {
		var calls []string
		action := func(phase string) error {
			calls = append(calls, phase)
			if phase == failAt {
				return errors.New("failure")
			}
			return nil
		}
		err := activateMigrationServices(action, func() error { return action("payload") }, func() error { return action("stop-target") })
		if failAt == "" {
			if err != nil || len(calls) != 4 {
				t.Fatalf("activation %v %v", calls, err)
			}
			continue
		}
		if err == nil || calls[len(calls)-1] != "stop-target" {
			t.Fatalf("failure did not fence target: %v %v", calls, err)
		}
		if failAt != "migration-bot" {
			for _, phase := range calls {
				if phase == "migration-bot" {
					t.Fatal("bot started before a valid full-path proof")
				}
			}
		}
	}
}
