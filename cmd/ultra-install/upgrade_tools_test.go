package main

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func writeToolFixture(t *testing.T, names []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.tar.gz")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zipped := gzip.NewWriter(file)
	archive := tar.NewWriter(zipped)
	for _, name := range names {
		if err = archive.WriteHeader(&tar.Header{Name: name, Size: 7, Mode: 0755, Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err = archive.Write([]byte("fixture")); err != nil {
			t.Fatal(err)
		}
	}
	for _, err := range []error{archive.Close(), zipped.Close(), file.Close()} {
		if err != nil {
			t.Fatal(err)
		}
	}
	return path
}
func TestUpgradeToolsRejectUnsafeOrIncompleteArchive(t *testing.T) {
	required := []string{
		"recovery.py",
		"monitor.py",
		"heartbeat.py",
		"reconcile.py",
		"ultra-recovery-backup.service",
		"ultra-recovery-backup.timer",
	}
	tools, err := extractUpgradeTools(writeToolFixture(t, required), filepath.Join(t.TempDir(), "tools"), map[string]string{})
	if err != nil || len(tools) != len(required) {
		t.Fatalf("complete bundle: %v", err)
	}
	if err = requireUpgradeTool(tools, "db_connection.py"); err == nil {
		t.Fatal("legacy baseline unexpectedly has the database recovery dependency")
	}
	current := append(append([]string{}, required...), "db_connection.py")
	tools, err = extractUpgradeTools(writeToolFixture(t, current), filepath.Join(t.TempDir(), "current-tools"), nil)
	if err != nil || len(tools) != len(current) {
		t.Fatalf("current bundle: %v", err)
	}
	if err = requireUpgradeTool(tools, "db_connection.py"); err != nil {
		t.Fatalf("current bundle missing database recovery dependency: %v", err)
	}
	for _, name := range []string{"../escape.py", "/absolute.py", "duplicate.py"} {
		invalid := append(append([]string{}, required...), name)
		if name == "duplicate.py" {
			invalid = append(invalid, name)
		}
		if _, err = extractUpgradeTools(writeToolFixture(t, invalid), filepath.Join(t.TempDir(), "tools"), nil); err == nil {
			t.Fatalf("unsafe member %s accepted", name)
		}
	}
	if _, err = extractUpgradeTools(writeToolFixture(t, required[:2]), filepath.Join(t.TempDir(), "tools"), nil); err == nil {
		t.Fatal("incomplete runtime archive accepted")
	}
}

func TestExitUpgradeIncludesRecoveryDependencies(t *testing.T) {
	for _, name := range []string{"recovery.py", "db_connection.py", "monitor.py", "heartbeat.py", "ultra-recovery-prune.service"} {
		if !isExitUpgradeRecoveryTool(name) {
			t.Errorf("exit upgrade omitted recovery tool %q", name)
		}
	}
	if isExitUpgradeRecoveryTool("ultra-client") {
		t.Fatal("exit recovery selector included unrelated client tool")
	}
}
