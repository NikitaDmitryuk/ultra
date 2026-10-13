package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sort"
	"sync/atomic"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/probe"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
)

// ProbeExit tests payload delivery through this exact outbound, not the current default route.
func (r *Runner) ProbeExit(ctx context.Context, n exits.Node, targets []string) exits.Health {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	h := exits.Health{ID: n.ID}
	if rtt, err := probe.DialTCP(ctx, n.DialAddr()); err == nil {
		h.Reachable = true
		h.TunnelLatencyMS = rtt.Milliseconds()
	}
	r.mu.Lock()
	inst := r.inst
	r.mu.Unlock()
	if inst == nil {
		return h
	}
	base := ctx
	tr := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 3 * time.Second, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := xnet.ParseDestination(network + ":" + addr)
			if err != nil {
				return nil, err
			}
			ctx = session.ContextWithContent(ctx, &session.Content{SkipDNSResolve: true})
			ctx = session.SetForcedOutboundTagToContext(ctx, exits.OutboundTag(n.ID))
			return core.Dial(ctx, inst, dest)
		}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ch := make(chan exits.ProbeResult, len(targets))
	for _, target := range targets {
		go func(target string) { ch <- checkBody(base, client, target) }(target)
	}
	for range targets {
		result := <-ch
		h.Checks = append(h.Checks, result)
		if result.OK {
			h.InternetOK = true
			if h.InternetLatencyMS == 0 || result.TTFBMS < h.InternetLatencyMS {
				h.InternetLatencyMS = result.TTFBMS
			}
		}
	}
	sort.Slice(h.Checks, func(i, j int) bool { return h.Checks[i].Target < h.Checks[j].Target })
	return h
}

func checkBody(ctx context.Context, client *http.Client, target string) exits.ProbeResult {
	result := exits.ProbeResult{Target: target}
	start := time.Now()
	var first atomic.Int64
	var handshakeStarted, handshakeFailed, handshakeCompleted atomic.Bool
	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() { first.Store(time.Since(start).Milliseconds()) },
		TLSHandshakeStart:    func() { handshakeStarted.Store(true) },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			handshakeFailed.Store(err != nil)
			handshakeCompleted.Store(err == nil)
		},
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, target, nil)
	if err == nil {
		req.Header.Set("Accept-Encoding", "identity")
		var resp *http.Response
		resp, err = client.Do(req)
		if err == nil {
			result.Bytes, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 65537))
			_ = resp.Body.Close()
			if err == nil && resp.StatusCode != http.StatusOK {
				result.Error = "http_status"
				err = fmt.Errorf("unexpected response")
			} else if err == nil && result.Bytes != 65536 {
				result.Error = "body_size"
				err = fmt.Errorf("unexpected response")
			}
		}
	}
	result.TTFBMS = first.Load()
	result.DurationMS = time.Since(start).Milliseconds()
	result.OK = err == nil
	if err != nil {
		if result.Error == "" {
			result.Error = "response_failed"
			if handshakeFailed.Load() {
				result.Error = "tls_handshake_failed"
			}
			if timeout, ok := err.(interface{ Timeout() bool }); ok && timeout.Timeout() {
				result.Error = "response_timeout"
				if handshakeStarted.Load() && !handshakeCompleted.Load() {
					result.Error = "tls_handshake_timeout"
				}
			}
		}
		if ctx.Err() != nil {
			result.Error = "deadline_or_cancel"
		}
	}
	return result
}
