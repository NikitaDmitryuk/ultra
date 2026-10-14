//go:build linux

package deployansible

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func requireCloseOnExec(t *testing.T, file *os.File) {
	t.Helper()
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), syscall.F_GETFD, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	if flags&syscall.FD_CLOEXEC == 0 {
		t.Fatal("lease descriptor can escape into unrelated exec children")
	}
}

func TestControllerLockDoesNotEscapeToExecChildren(t *testing.T) {
	path := filepath.Join(t.TempDir(), "infrastructure.lock")
	file, err := controllerLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close() //nolint:errcheck
	requireCloseOnExec(t, file)
	script := fmt.Sprintf("import os; p='/proc/self/fd/%d'; print(os.readlink(p) if os.path.exists(p) else '')", file.Fd())
	output, err := exec.Command("python3", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(output)) == path {
		t.Fatal("unrelated child inherited infrastructure lease")
	}
	retained, err := retainInfrastructureLock(file, path)
	if err != nil {
		t.Fatal(err)
	}
	defer retained.Close() //nolint:errcheck
	requireCloseOnExec(t, retained)
}
