package installplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDatabaseDumpBindingAndPrivacy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "database.dump")
	if err := os.WriteFile(path, []byte("PGDMPsynthetic archive"), 0600); err != nil {
		t.Fatal(err)
	}
	sum, err := DatabaseDumpDigest(path)
	if err != nil || len(sum) != 64 {
		t.Fatalf("digest %q %v", sum, err)
	}
	if err := os.WriteFile(path, []byte("PGDMPchanged archive"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDatabaseDump(path, sum); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("changed archive accepted: %v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := DatabaseDumpDigest(path); err == nil {
		t.Fatal("public dump accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := DatabaseDumpDigest(link); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.WriteFile(path, []byte("text backup"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := DatabaseDumpDigest(path); err == nil {
		t.Fatal("plain SQL accepted")
	}
}

func TestDatabaseDumpLocalListingBeforeDispatch(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "database.dump")
	os.WriteFile(path, []byte("PGDMPsynthetic archive"), 0600)
	sum, _ := DatabaseDumpDigest(path)
	os.WriteFile(filepath.Join(root, "pg_restore"), []byte("#!/bin/sh\n[ \"$1\" = --list ] || exit 3\nexit 0\n"), 0700)
	t.Setenv("PATH", root)
	if err := VerifyDatabaseDump(path, sum); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "pg_restore"), []byte("#!/bin/sh\nexit 1\n"), 0700)
	if err := VerifyDatabaseDump(path, sum); err == nil {
		t.Fatal("invalid listing accepted")
	}
}
