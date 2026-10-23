package deployansible

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"sync"
	"syscall"
)

var localExecutionState struct {
	sync.RWMutex
	path string
}

var lookupExecutionAccount = user.LookupId // Replaced only by account metadata fixtures.

// ExpectedLocalExecutionState returns the single durable admission namespace
// for this account. Account metadata, never HOME, SUDO_USER, XDG or job paths,
// determines the namespace shared by every local operation.
func ExpectedLocalExecutionState() (string, error) {
	if os.Geteuid() == 0 {
		return "/var/lib/ultra-ansible", nil
	}
	account, err := lookupExecutionAccount(strconv.Itoa(os.Geteuid()))
	if err != nil || !filepath.IsAbs(account.HomeDir) || filepath.Clean(account.HomeDir) != account.HomeDir {
		return "", errors.New("execution_account_home_unavailable")
	}
	return filepath.Join(account.HomeDir, ".local", "state", "ultra-ansible"), nil
}

// ConfigureLocalExecutionState admits only the fixed account namespace. The
// caller must explicitly select it before dispatch; choosing a second workspace
// cannot create another independent mutation fence.
func ConfigureLocalExecutionState(path string) error {
	expected, err := ExpectedLocalExecutionState()
	if err != nil {
		return err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path != expected {
		return errors.New("execution_state_namespace_invalid")
	}
	if err = secureExecutionState(path); err != nil {
		return err
	}
	localExecutionState.Lock()
	defer localExecutionState.Unlock()
	localExecutionState.path = path
	return nil
}

func secureExecutionState(path string) error {
	// Walk with directory FDs: concurrent ancestor replacement must not redirect
	// creation through a symlink between validation and mkdir/open.
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("execution_namespace_insecure")
	}
	defer func() { _ = syscall.Close(fd) }()
	parts := splitAbsolutePath(path)
	for i, part := range parts {
		next, e := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if e == syscall.ENOENT {
			if e = syscall.Mkdirat(fd, part, 0700); e == nil || e == syscall.EEXIST {
				next, e = syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
			}
		}
		if e != nil {
			return errors.New("execution_namespace_insecure")
		}
		var st syscall.Stat_t
		e = syscall.Fstat(next, &st)
		if e != nil || st.Mode&0022 != 0 || st.Uid != 0 && st.Uid != uint32(os.Geteuid()) ||
			i == len(parts)-1 && (st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0700) {
			_ = syscall.Close(next)
			return errors.New("execution_namespace_insecure")
		}
		_ = syscall.Close(fd)
		fd = next
	}
	return nil
}

func splitAbsolutePath(path string) []string {
	var parts []string
	for path != "/" {
		parts = append([]string{filepath.Base(path)}, parts...)
		path = filepath.Dir(path)
	}
	return parts
}

func requireConfiguredExecutionState() error {
	if os.Geteuid() == 0 {
		return nil
	}
	expected, err := ExpectedLocalExecutionState()
	if err != nil {
		return err
	}
	localExecutionState.RLock()
	configured := localExecutionState.path
	localExecutionState.RUnlock()
	if configured != expected {
		return errors.New("execution_state_configuration_required")
	}
	return secureExecutionState(expected)
}

// Only package tests (and their explicit linkname fixtures) replace this
// unexported resolver. Arbitrary production paths never disable containment.
func executionNamespaceFixture() bool {
	return reflect.ValueOf(executionFenceDirectory).Pointer() != reflect.ValueOf(productionExecutionFenceDirectory).Pointer()
}

func executionManagerArgs(args ...string) []string {
	if os.Geteuid() != 0 {
		return append([]string{"--user"}, args...)
	}
	return args
}

var regexpExecutionUnit = regexp.MustCompile(`^ultra-(?:deploy-[a-f0-9]{64}|execution-[a-f0-9]{32}|ansible-controller|recovery-reconcile)\.service$`)

func executionUnitGroup(unit, observed string) (string, error) {
	if !regexpExecutionUnit.MatchString(unit) {
		return "", ErrExecutionFenced
	}
	prefix := "/system.slice/"
	if os.Geteuid() != 0 {
		uid := strconv.Itoa(os.Geteuid())
		prefix = "/user.slice/user-" + uid + ".slice/user@" + uid + ".service/app.slice/"
	}
	expected := prefix + unit
	if observed != "" && observed != expected {
		return "", ErrExecutionFenced
	}
	return expected, nil
}

func executionManagerCommand(ctxCommand *exec.Cmd) *exec.Cmd {
	// Avoid an inherited alternate bus selecting a different manager. The
	// private per-UID runtime directory is checked before mutating dispatch.
	ctxCommand.Env = []string{"PATH=/usr/bin:/bin"}
	if os.Geteuid() != 0 {
		ctxCommand.Env = append(ctxCommand.Env, "XDG_RUNTIME_DIR=/run/user/"+strconv.Itoa(os.Geteuid()))
	}
	return ctxCommand
}
