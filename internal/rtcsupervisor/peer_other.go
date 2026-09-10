//go:build !linux

package rtcsupervisor

import "net"

func PeerAllowed(_ *net.UnixConn, _ int) bool { return false }
