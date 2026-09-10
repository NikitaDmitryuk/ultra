package proxy

import (
	"context"
	"errors"
	"net"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
)

type rtcProbeContext struct{}

// DialRTC accepts a server-derived owner; never use an identity from client input.
func (r *Runner) DialRTC(ctx context.Context, owner, addr string, probe bool) (net.Conn, error) {
	r.mu.Lock()
	inst := r.inst
	r.mu.Unlock()
	if inst == nil {
		return nil, errors.New("rtc routing unavailable")
	}
	dest, e := xnet.ParseDestination("tcp:" + addr)
	if e != nil {
		return nil, errors.New("invalid destination")
	}
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: "rtc-service", Source: xnet.TCPDestination(xnet.LocalHostIP, 0), User: &protocol.MemoryUser{Email: owner, Level: 1}})
	if probe {
		ctx = context.WithValue(ctx, rtcProbeContext{}, true)
	}
	return core.Dial(ctx, inst, dest)
}
