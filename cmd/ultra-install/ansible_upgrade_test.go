package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnsibleUpgradeRequiresForwardSchemaCompatibleFallback(t *testing.T) {
	previous := &automationRelease{DatabaseSchemaMin: 24, DatabaseSchemaMax: 25, Capabilities: []string{"service-access-v1", "provider-pool-quota-v1"}}
	target := *previous
	if err := compatibleAnsibleRelease(previous, &target); err != nil {
		t.Fatal(err)
	}
	target.DatabaseSchemaMax = 26
	if compatibleAnsibleRelease(previous, &target) == nil {
		t.Fatal("fallback lacking post-migration schema accepted")
	}
	target = *previous
	target.Capabilities = []string{"service-access-v1"}
	if compatibleAnsibleRelease(previous, &target) == nil {
		t.Fatal("ledger incompatible target accepted")
	}
	target = *previous
	target.DatabaseSchemaMin = 0
	if compatibleAnsibleRelease(previous, &target) == nil {
		t.Fatal("missing schema contract accepted")
	}
}

func TestUpgradeInputIsPrivateImmutableAndRejectsSymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input")
	if err := writeUpgradeInput(path, []byte("fixture")); err != nil {
		t.Fatal(err)
	}
	if err := writeUpgradeInput(path, []byte("fixture")); err != nil {
		t.Fatal(err)
	}
	if writeUpgradeInput(path, []byte("changed")) == nil {
		t.Fatal("changed frozen input accepted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if writeUpgradeInput(path, []byte("fixture")) == nil {
		t.Fatal("public private material accepted")
	}
	symlink := filepath.Join(t.TempDir(), "symlink")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if writeUpgradeInput(symlink, []byte("fixture")) == nil {
		t.Fatal("symlinked input accepted")
	}
}
