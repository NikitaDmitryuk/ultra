package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/proto"
)

const managedXHTTP = "ultra-managed-xhttp"

// The pinned XHTTP Listener.Close closes only the accept socket, leaving HTTP/2
// connections serving the old instance. Own the encrypted TCP connections while
// retaining the official transport over a private Unix socket. PROXY preserves
// the peer address; TLS/REALITY and the XHTTP bytes are not terminated or changed.
func init() {
	common.Must(internet.RegisterTransportListener(managedXHTTP, listenManagedXHTTP))
}
func manageXHTTPListeners(cfg *core.Config) error {
	for _, in := range cfg.Inbound {
		if in.ReceiverSettings == nil {
			continue
		}
		value, e := in.ReceiverSettings.GetInstance()
		if e != nil {
			return e
		}
		receiver, ok := value.(*proxyman.ReceiverConfig)
		if !ok || receiver.StreamSettings == nil {
			continue
		}
		stream := receiver.StreamSettings
		if stream.ProtocolName != "splithttp" {
			continue
		}
		stream.ProtocolName = managedXHTTP
		for _, setting := range stream.TransportSettings {
			if setting.ProtocolName == "splithttp" {
				setting.ProtocolName = managedXHTTP
			}
		}
		in.ReceiverSettings = serial.ToTypedMessage(receiver)
	}
	return nil
}

type managedXHTTPListener struct {
	net.Listener
	backend internet.Listener
	dir     string
	mu      sync.Mutex
	closed  bool
	conns   map[net.Conn]struct{}
	wg      sync.WaitGroup
}

func listenManagedXHTTP(ctx context.Context, address xnet.Address, port xnet.Port, settings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	// HTTP/3 has its own correctly closed server; this workaround is TCP-only.
	if tls, ok := settings.SecuritySettings.(*xtls.Config); ok && len(tls.NextProtocol) == 1 && tls.NextProtocol[0] == "h3" {
		return splithttp.ListenXH(ctx, address, port, settings, handler)
	}
	var addr net.Addr
	if port == 0 {
		addr = &net.UnixAddr{Name: address.Domain(), Net: "unix"}
	} else {
		addr = &net.TCPAddr{IP: address.IP(), Port: int(port)}
	}
	front, e := internet.ListenSystem(ctx, addr, settings.SocketSettings)
	if e != nil {
		return nil, e
	}
	dir, e := os.MkdirTemp("", "ultra-xh-")
	if e != nil {
		_ = front.Close()
		return nil, e
	}
	private := *settings
	// Only the process can reach the 0700 socket directory and supply PROXY headers.
	private.SocketSettings = &internet.SocketConfig{AcceptProxyProtocol: true}
	if settings.SocketSettings != nil {
		private.SocketSettings = proto.Clone(settings.SocketSettings).(*internet.SocketConfig)
		private.SocketSettings.AcceptProxyProtocol = true
	}
	backend, e := splithttp.ListenXH(ctx, xnet.DomainAddress(filepath.Join(dir, "s")), 0, &private, handler)
	if e != nil {
		_ = front.Close()
		_ = os.RemoveAll(dir)
		return nil, e
	}
	l := &managedXHTTPListener{Listener: front, backend: backend, dir: dir, conns: map[net.Conn]struct{}{}}
	l.wg.Add(1)
	go l.serve(filepath.Join(dir, "s"))
	return l, nil
}
func (l *managedXHTTPListener) serve(socket string) {
	defer l.wg.Done()
	for {
		c, e := l.Accept()
		if e != nil {
			return
		}
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			_ = c.Close()
			return
		}
		l.conns[c] = struct{}{}
		l.wg.Add(1)
		l.mu.Unlock()
		go l.forward(c, socket)
	}
}
func (l *managedXHTTPListener) forward(c net.Conn, socket string) {
	defer l.wg.Done()
	defer func() { _ = c.Close() }()
	defer func() { l.mu.Lock(); delete(l.conns, c); l.mu.Unlock() }()
	target, e := net.DialTimeout("unix", socket, 3*time.Second)
	if e != nil {
		return
	}
	defer func() { _ = target.Close() }()
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.conns[target] = struct{}{}
	l.mu.Unlock()
	defer func() { l.mu.Lock(); delete(l.conns, target); l.mu.Unlock() }()
	header := "PROXY UNKNOWN\r\n"
	src, srcOK := c.RemoteAddr().(*net.TCPAddr)
	dst, dstOK := c.LocalAddr().(*net.TCPAddr)
	if srcOK && dstOK {
		family := "TCP6"
		if src.IP.To4() != nil {
			family = "TCP4"
		}
		header = fmt.Sprintf("PROXY %s %s %s %d %d\r\n", family, src.IP.String(), dst.IP.String(), src.Port, dst.Port)
	}
	_ = target.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, e = io.WriteString(target, header); e != nil {
		return
	}
	_ = target.SetWriteDeadline(time.Time{})
	done := make(chan struct{})
	go func() { _, _ = io.Copy(target, c); _ = target.Close(); close(done) }()
	_, _ = io.Copy(c, target)
	_ = c.Close()
	_ = target.Close()
	<-done
}
func (l *managedXHTTPListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	err := l.Listener.Close()
	for c := range l.conns {
		_ = c.Close()
	}
	l.mu.Unlock()
	backendErr := l.backend.Close()
	l.wg.Wait()
	_ = os.RemoveAll(l.dir)
	if err != nil {
		return err
	}
	return backendErr
}
