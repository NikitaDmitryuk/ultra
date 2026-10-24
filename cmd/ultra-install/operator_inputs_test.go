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

func TestOperatorStateRootRequiresPasswdDefaultForNonroot(t *testing.T) {
	home := "/home/operator"
	want := filepath.Join(home, ".local", "state", "ultra-ansible")
	if got, err := resolveOperatorStateRoot(1000, want, home); err != nil || got != want {
		t.Fatalf("nonroot state root: %q %v", got, err)
	}
	for _, requested := range []string{"", filepath.Join(home, "other"), "relative"} {
		if _, err := resolveOperatorStateRoot(1000, requested, home); err == nil {
			t.Fatalf("nonroot accepted state root %q", requested)
		}
	}
	if got, err := resolveOperatorStateRoot(0, "", ""); err != nil || got != "" {
		t.Fatalf("root legacy namespace: %q %v", got, err)
	}
}
