//go:build linux

package rtcsupervisor

import (
	"golang.org/x/sys/unix"
	"net"
)

func PeerAllowed(c *net.UnixConn, uid int) bool {
	raw, e := c.SyscallConn()
	if e != nil {
		return false
	}
	ok := false
	e = raw.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		ok = e == nil && int(cred.Uid) == uid
	})
	return e == nil && ok
}
