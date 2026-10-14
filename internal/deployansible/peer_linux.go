//go:build linux

package deployansible

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var controlErr error
	err = raw.Control(func(fd uintptr) {
		credentials, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		controlErr = e
		if e == nil {
			uid = credentials.Uid
		}
	})
	if err != nil {
		return 0, err
	}
	return uid, controlErr
}

func controllerLock(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func isolateCommand(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = 5 * time.Second
}

func ownedByProcess(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func retainInfrastructureLock(file *os.File, path string) (*os.File, error) {
	expected, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	offered, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !expected.Mode().IsRegular() || expected.Mode().Perm()&0077 != 0 || !ownedByProcess(expected) || !os.SameFile(expected, offered) {
		return nil, os.ErrPermission
	}
	fd, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		return nil, err
	}
	syscall.CloseOnExec(fd)
	retained := os.NewFile(uintptr(fd), path)
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = retained.Close()
		return nil, err
	}
	return retained, nil
}

func controllerLockBusy(err error) bool { return errors.Is(err, syscall.EWOULDBLOCK) }
