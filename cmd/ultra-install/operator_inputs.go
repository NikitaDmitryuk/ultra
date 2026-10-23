package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

func requireRootOperator() error {
	if os.Geteuid() != 0 {
		return errors.New("operator_root_required")
	}
	return nil
}

func resolveOperatorStateRoot(uid uint32, requested, home string) (string, error) {
	if requested == "" {
		if uid == 0 {
			return "", nil // preserve the legacy root namespace
		}
		return "", errors.New("operator_state_dir_required")
	}
	if !filepath.IsAbs(requested) || filepath.Clean(requested) != requested {
		return "", errors.New("operator_state_dir_invalid")
	}
	if uid != 0 {
		if !filepath.IsAbs(home) || filepath.Clean(home) != home || requested != filepath.Join(home, ".local", "state", "ultra-ansible") {
			return "", errors.New("operator_state_dir_must_be_passwd_default")
		}
	}
	return requested, nil
}

func configureOperatorExecutionState(requested string) error {
	uid := uint32(os.Geteuid())
	var home string
	if uid != 0 {
		entry, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
		if err != nil || entry.HomeDir == "" {
			return errors.New("operator_state_home_unavailable")
		}
		home = entry.HomeDir
	}
	root, err := resolveOperatorStateRoot(uid, requested, home)
	if err != nil || root == "" {
		return err
	}
	return deployansible.ConfigureLocalExecutionState(root)
}

// The UID argument is explicit so fixtures can exercise the same checks without
// privileged chown. Callers pass their operator UID; retained recovery requires zero.
func openOperatorLock(path string, uid uint32) (*os.File, error) {
	if err := rebuildNoSymlinkAncestors(filepath.Dir(path)); err != nil {
		return nil, errors.New("operator_lock_unsafe")
	}
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errors.New("operator_lock_unavailable")
	}
	f := os.NewFile(uintptr(fd), path)
	fail := func(code string) (*os.File, error) { _ = f.Close(); return nil, errors.New(code) }
	info, err := f.Stat()
	if err != nil {
		return fail("operator_lock_unsafe")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Nlink != 1 {
		return fail("operator_lock_unsafe")
	}
	if st.Uid != uid {
		return fail("operator_lock_owner_mismatch")
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fail("operator_lock_busy")
	}
	return f, nil
}

// Keep the directory inode locked for the whole attempt; a second config must
// not admit the same empty workspace concurrently.
func openRetainedWorkspace(path string, uid uint32) (*os.File, error) {
	if err := rebuildNoSymlinkAncestors(filepath.Dir(path)); err != nil {
		return nil, errors.New("retained_primary_workspace_unsafe")
	}
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return nil, errors.New("retained_primary_new_workspace_required")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("retained_primary_workspace_unsafe")
	}
	f := os.NewFile(uintptr(fd), path)
	fail := func(code string) (*os.File, error) { _ = f.Close(); return nil, errors.New(code) }
	info, err := f.Stat()
	if err != nil {
		return fail("retained_primary_workspace_unsafe")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || st.Uid != uid || info.Mode().Perm() != 0700 {
		return fail("retained_primary_workspace_unsafe")
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fail("retained_primary_workspace_busy")
	}
	if entries, e := f.Readdirnames(1); len(entries) != 0 || e != io.EOF {
		return fail("retained_primary_new_workspace_required")
	}
	return f, nil
}

func retainedRuntimePreflight(python, ansible string) error {
	for _, path := range []string{python, ansible} {
		if !filepath.IsAbs(path) {
			return errors.New("retained_primary_runtime_path_invalid")
		}
		// Python/venv entrypoints may be system-owned symlinks. Validate their
		// resolved target and every ancestor before accepting executable code.
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || !trustedOperatorExecutable(resolved) || !trustedOperatorParents(path) {
			return errors.New("retained_primary_runtime_unavailable")
		}
	}
	for _, name := range []string{"ssh", "age", "pg_restore"} {
		path, err := exec.LookPath(name)
		if err != nil || !trustedOperatorExecutable(path) || !trustedOperatorParents(path) {
			return errors.New("retained_primary_tool_unavailable: " + name)
		}
	}
	return nil
}

func trustedOperatorExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	uid := uint32(os.Geteuid())
	return ok && (st.Uid == 0 || st.Uid == uid) && trustedOperatorParents(path)
}

func trustedOperatorParents(path string) bool {
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return false
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		uid := uint32(os.Geteuid())
		if !ok || (st.Uid != 0 && st.Uid != uid) {
			return false
		}
		if filepath.Dir(dir) == dir {
			return true
		}
	}
}
