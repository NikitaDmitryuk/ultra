package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestCrashAfterBrokerPreparationKeepsAttemptModeAndReservationID(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ULTRA_INSTALL_STATE_DIR", root)
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	stateRoot, err := bootstrapStateRoot()
	if err != nil {
		t.Fatal(err)
	}
	planRoot := filepath.Join(stateRoot, "bootstrap-fixture")
	if err = ensurePrivateBootstrapDirectory(planRoot); err != nil {
		t.Fatal(err)
	}
	_, release, err := withBootstrapOperatorLock(context.Background(), stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := beginBootstrapAttempt(planRoot)
	if err != nil {
		t.Fatal(err)
	}
	p := &installplan.InstallPlan{Bridge: installplan.BridgeConfig{SSHHost: "198.18.0.10", Address: "198.18.0.10"}}
	remote := false
	p.ControllerLocal = &remote
	p.ControllerLocalTarget = p.Bridge.SSHHost + "|" + p.Bridge.Address
	lockRoot, err := freezeBootstrapExecution(p, directory, stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if lockRoot != stateRoot {
		t.Fatal("fresh gateway lock moved to target state")
	}
	modeRaw, err := os.ReadFile(filepath.Join(directory, "execution-mode.json"))
	if err != nil {
		t.Fatal(err)
	}
	var mode frozenExecution
	if json.Unmarshal(modeRaw, &mode) != nil || mode.OperatorDirectory != filepath.Join(stateRoot, "operator") {
		t.Fatal("original operator directory not frozen")
	}
	id := lifecycleID(directory)
	release() // Process exits after preparing broker; incomplete attempt is retained.
	laterRoot, err := bootstrapStateRoot()
	if err != nil {
		t.Fatal(err)
	}
	if laterRoot != stateRoot {
		t.Fatal("broker appearance changed journal location")
	}
	_, release, err = withBootstrapOperatorLock(context.Background(), laterRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	resumed, err := beginBootstrapAttempt(planRoot)
	if err != nil {
		t.Fatal(err)
	}
	if resumed != directory || lifecycleID(resumed) != id {
		t.Fatal("restart lost the reserved attempt")
	}
	installed := true
	p2 := &installplan.InstallPlan{Bridge: p.Bridge, ControllerLocal: &installed, ControllerLocalTarget: p.ControllerLocalTarget}
	resumedLock, err := freezeBootstrapExecution(p2, resumed, laterRoot)
	if err != nil {
		t.Fatal(err)
	}
	if resumedLock != lockRoot || localLifecycleBridge(p2) {
		t.Fatal("installed broker silently switched a frozen gateway into local mode")
	}
}
func TestFrozenExecutionRejectsPublicJournalAndChangedTarget(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	p := &installplan.InstallPlan{Bridge: installplan.BridgeConfig{SSHHost: "198.18.0.10", Address: "198.18.0.10"}}
	remote := false
	p.ControllerLocal = &remote
	p.ControllerLocalTarget = p.Bridge.SSHHost + "|" + p.Bridge.Address
	if _, err := freezeBootstrapExecution(p, root, root); err != nil {
		t.Fatal(err)
	}
	p.Bridge.SSHHost = "198.18.0.11"
	if _, err := freezeBootstrapExecution(p, root, root); err == nil {
		t.Fatal("resume changed target")
	}
	p.Bridge.SSHHost = "198.18.0.10"
	if err := os.Chmod(filepath.Join(root, "execution-mode.json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := freezeBootstrapExecution(p, root, root); err == nil {
		t.Fatal("public execution record accepted")
	}
}

func TestFrozenExecutionRejectsChangedOperatorDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	remote := false
	p := &installplan.InstallPlan{Bridge: installplan.BridgeConfig{SSHHost: "192.0.2.1", Address: "192.0.2.1"}, ControllerLocal: &remote, ControllerLocalTarget: "192.0.2.1|192.0.2.1"}
	if _, err := freezeBootstrapExecution(p, root, root); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "execution-mode.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var mode frozenExecution
	if err = json.Unmarshal(raw, &mode); err != nil {
		t.Fatal(err)
	}
	mode.OperatorDirectory = filepath.Join(root, "different-operator")
	raw, _ = json.Marshal(mode)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = freezeBootstrapExecution(p, root, root); err == nil {
		t.Fatal("changed original operator directory accepted")
	}
}
