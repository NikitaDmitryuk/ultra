package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A non-root run used to pass every CLI and SSH check, create the durable
// one-shot admission on the fleet, and only then fail inside the executor with no
// receipt. The preflight must run first and must not leave a workspace behind.
func TestRetainedCLIPreflightPrecedesWorkspaceAndFleet(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	original := retainedLocalExecutionPreflight
	retainedLocalExecutionPreflight = func() error {
		return errors.New("execution_containment_unverified")
	}
	defer func() { retainedLocalExecutionPreflight = original }()
	args := []string{
		"--config", filepath.Join(root, "config.json"),
		"--manifest", filepath.Join(root, "manifest.json"),
		"--original-journal", filepath.Join(root, "journal.json"),
		"--state-dir", state,
		"--backup", filepath.Join(root, "backup.age"),
		"--backup-sha256", strings.Repeat("a", 64),
		"--executable", filepath.Join(root, "ansible-playbook"),
		"--accept-reimaged-fleet",
	}
	args = append(args, operatorStateArgsForCurrentTest(t)...)
	err := runRetainedPrimaryCommand(args)
	if err == nil || !strings.Contains(err.Error(), "execution_containment_unverified") {
		t.Fatalf("preflight failure not reported: %v", err)
	}
	if _, statErr := os.Lstat(state); !os.IsNotExist(statErr) {
		t.Fatal("failed preflight created the one-shot workspace")
	}
}

// A passing preflight must not change the existing scope and input contracts.
func TestRetainedCLIPreflightKeepsInputValidation(t *testing.T) {
	root := t.TempDir()
	original := retainedLocalExecutionPreflight
	retainedLocalExecutionPreflight = func() error { return nil }
	defer func() { retainedLocalExecutionPreflight = original }()
	err := runRetainedPrimaryCommand([]string{
		"--config", filepath.Join(root, "config.json"),
		"--manifest", filepath.Join(root, "manifest.json"),
		"--original-journal", filepath.Join(root, "journal.json"),
		"--state-dir", filepath.Join(root, "state"),
		"--backup", filepath.Join(root, "backup.age"),
		"--backup-sha256", strings.Repeat("a", 64),
		"--executable", filepath.Join(root, "ansible-playbook"),
		"--accept-reimaged-fleet",
	})
	if err == nil {
		t.Fatal("absent operator config accepted")
	}
	if strings.Contains(err.Error(), "preflight") {
		t.Fatalf("preflight masked input validation: %v", err)
	}
}
