//go:build !linux

package deployansible

import (
	"errors"
	"net"
	"os"
	"os/exec"
)

func peerUID(_ *net.UnixConn) (uint32, error) {
	return 0, errors.New("controller requires Linux peer credentials")
}

func controllerLock(_ string) (*os.File, error) {
	return nil, errors.New("controller requires Linux advisory locking")
}

func isolateCommand(_ *exec.Cmd) {}

func ownedByProcess(_ os.FileInfo) bool { return false }

func retainInfrastructureLock(_ *os.File, _ string) (*os.File, error) {
	return nil, errors.New("controller requires Linux")
}

func controllerLockBusy(_ error) bool { return false }
