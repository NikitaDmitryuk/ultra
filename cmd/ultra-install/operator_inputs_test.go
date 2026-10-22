package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOperatorLockProtection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	uid := uint32(os.Geteuid())
	first, err := openOperatorLock(path, uid)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	if _, err = openOperatorLock(path, uid); err == nil || err.Error() != "operator_lock_busy" {
		t.Fatalf("busy: %v", err)
	}
	if _, err = openOperatorLock(path, uid+1); err == nil || err.Error() != "operator_lock_owner_mismatch" {
		t.Fatalf("owner: %v", err)
	}
	if err = os.Chmod(path, 0620); err != nil {
		t.Fatal(err)
	}
	if _, err = openOperatorLock(path, uid); err == nil {
		t.Fatal("group writable lock accepted")
	}
}

func TestOperatorLockRejectsLinks(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "lock")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, filepath.Join(root, "hard")); err != nil {
		t.Fatal(err)
	}
	if _, err := openOperatorLock(path, uint32(os.Geteuid())); err == nil {
		t.Fatal("hard link accepted")
	}
	link := filepath.Join(root, "sym")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openOperatorLock(link, uint32(os.Geteuid())); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestRetainedWorkspaceAdmission(t *testing.T) {
	for _, existing := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "state")
		if existing {
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
		}
		file, err := openRetainedWorkspace(path, uint32(os.Geteuid()))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = openRetainedWorkspace(path, uint32(os.Geteuid())); err == nil {
			t.Fatal("concurrent admission")
		}
		_ = file.Close()
		if _, err = openRetainedWorkspace(path, uint32(os.Geteuid())+1); err == nil {
			t.Fatal("foreign owner accepted")
		}
		if err = os.WriteFile(filepath.Join(path, "evidence"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = openRetainedWorkspace(path, uint32(os.Geteuid())); err == nil {
			t.Fatal("nonempty accepted")
		}
	}
}
