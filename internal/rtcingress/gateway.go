// Package rtcingress implements authenticated, dynamically revocable RTC ingress.
package rtcingress

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/google/uuid"
)

type DialFunc func(context.Context, string, string, bool) (net.Conn, error)
type credential struct {
	Owner, Generation, Password string
	Probe                       bool
}
type Gateway struct {
	closed       bool
	ProbeAddress string
	mu           sync.Mutex
	credentials  map[string]credential
	conns        map[net.Conn]credential
	usage        map[usageKey]db.RTCUsage
	epoch        string
	listener     net.Listener
	dial         DialFunc
	eligible     func(context.Context, string) bool
	wg           sync.WaitGroup
}
type usageKey struct {
	Owner string
	Hour  time.Time
}

func NewGateway(dial DialFunc, eligible func(context.Context, string) bool) *Gateway {
	return &Gateway{credentials: map[string]credential{}, conns: map[net.Conn]credential{}, usage: map[usageKey]db.RTCUsage{}, epoch: uuid.NewString(), dial: dial, eligible: eligible}
}
func (g *Gateway) Set(user string, c credential) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.credentials[user] = c
}
func (g *Gateway) Revoke(owner string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, c := range g.credentials {
		if c.Owner == owner {
			delete(g.credentials, k)
		}
	}
	for conn, c := range g.conns {
		if c.Owner == owner {
			_ = conn.Close()
		}
	}
}
func (g *Gateway) Serve(l net.Listener) {
	g.mu.Lock()
	g.listener = l
	g.mu.Unlock()
	for {
		c, e := l.Accept()
		if e != nil {
			return
		}
		g.mu.Lock()
		if g.closed {
			g.mu.Unlock()
			_ = c.Close()
			return
		}
		g.conns[c] = credential{}
		g.wg.Add(1)
		g.mu.Unlock()
		go func() { defer g.wg.Done(); g.handle(c) }()
	}
}
func (g *Gateway) Close() {
	g.mu.Lock()
	g.closed = true
	if g.listener != nil {
		_ = g.listener.Close()
	}
	for c := range g.conns {
		_ = c.Close()
	}
	g.mu.Unlock()
	g.wg.Wait()
}
func (g *Gateway) handle(c net.Conn) {
	defer func() { _ = c.Close(); g.mu.Lock(); delete(g.conns, c); g.mu.Unlock() }()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	head := make([]byte, 2)
	if _, e := io.ReadFull(c, head); e != nil || head[0] != 5 || head[1] == 0 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, e := io.ReadFull(c, methods); e != nil {
		return
	}
	auth := false
	for _, m := range methods {
		auth = auth || m == 2
	}
	if !auth {
		_, _ = c.Write([]byte{5, 255})
		return
	}
	if _, e := c.Write([]byte{5, 2}); e != nil {
		return
	}
	if _, e := io.ReadFull(c, head); e != nil || head[0] != 1 || head[1] == 0 {
		return
	}
	user := make([]byte, int(head[1]))
	if _, e := io.ReadFull(c, user); e != nil {
		return
	}
	n := make([]byte, 1)
	if _, e := io.ReadFull(c, n); e != nil || n[0] == 0 {
		return
	}
	pass := make([]byte, int(n[0]))
	if _, e := io.ReadFull(c, pass); e != nil {
		return
	}
	g.mu.Lock()
	cred, ok := g.credentials[string(user)]
	g.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	eligible := ok && g.eligible(ctx, cred.Owner)
	cancel()
	g.mu.Lock()
	current, still := g.credentials[string(user)]
	count := 0
	for _, v := range g.conns {
		if v.Owner == cred.Owner {
			count++
		}
	}
	ok = eligible && still && current == cred && subtle.ConstantTimeCompare(pass, []byte(cred.Password)) == 1 && count < 64
	if ok {
		g.conns[c] = cred
	}
	g.mu.Unlock()
	if !ok {
		_, _ = c.Write([]byte{1, 1})
		return
	}
	if _, e := c.Write([]byte{1, 0}); e != nil {
		return
	}
	h := make([]byte, 4)
	if _, e := io.ReadFull(c, h); e != nil || h[0] != 5 || h[1] != 1 || h[2] != 0 {
		return
	}
	var host string
	switch h[3] {
	case 1:
		b := make([]byte, 4)
		if _, e := io.ReadFull(c, b); e != nil {
			return
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, e := io.ReadFull(c, b); e != nil {
			return
		}
		host = net.IP(b).String()
	case 3:
		if _, e := io.ReadFull(c, n); e != nil || n[0] == 0 {
			return
		}
		b := make([]byte, int(n[0]))
		if _, e := io.ReadFull(c, b); e != nil {
			return
		}
		host = string(b)
	default:
		return
	}
	port := make([]byte, 2)
	if _, e := io.ReadFull(c, port); e != nil {
		return
	}
	p := int(port[0])<<8 | int(port[1])
	if p == 0 {
		return
	}
	cred.Probe = cred.Probe && net.JoinHostPort(host, strconv.Itoa(p)) == g.ProbeAddress
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	remote, e := g.dial(ctx, cred.Owner, net.JoinHostPort(host, strconv.Itoa(p)), cred.Probe)
	if e != nil {
		_, _ = c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer func() { _ = remote.Close() }()
	if _, e = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); e != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() { defer close(done); g.copy(remote, c, cred, true); cancel(); _ = remote.Close(); _ = c.Close() }()
	g.copy(c, remote, cred, false)
	cancel()
	_ = remote.Close()
	_ = c.Close()
	<-done
}
func (g *Gateway) copy(dst io.Writer, src io.Reader, c credential, up bool) {
	b := make([]byte, 32768)
	for {
		n, e := src.Read(b)
		if n > 0 {
			w, we := dst.Write(b[:n])
			if !c.Probe && w > 0 {
				g.mu.Lock()
				key := usageKey{c.Owner, time.Now().UTC().Truncate(time.Hour)}
				u := g.usage[key]
				u.Hour = key.Hour
				if up {
					u.Up += int64(w)
				} else {
					u.Down += int64(w)
				}
				g.usage[key] = u
				g.mu.Unlock()
			}
			if we != nil || w != n {
				return
			}
		}
		if e != nil {
			return
		}
	}
}
func (g *Gateway) Flush(ctx context.Context, r interface {
	SaveUsage(context.Context, string, string, db.RTCUsage) error
}) error {
	g.mu.Lock()
	snapshot := make(map[usageKey]db.RTCUsage, len(g.usage))
	for k, u := range g.usage {
		snapshot[k] = u
	}
	g.mu.Unlock()
	var result error
	for k, u := range snapshot {
		if e := r.SaveUsage(ctx, k.Owner, g.epoch, u); e != nil {
			result = errors.New("rtc statistics unavailable")
			continue
		}
		if k.Hour.Before(time.Now().UTC().Truncate(time.Hour)) {
			g.mu.Lock()
			if g.usage[k] == u {
				delete(g.usage, k)
			}
			g.mu.Unlock()
		}
	}
	return result
}

func (g *Gateway) Grant(owner, generation, password string, probe bool) {
	g.Set(generation, credential{Owner: owner, Generation: generation, Password: password, Probe: probe})
}
