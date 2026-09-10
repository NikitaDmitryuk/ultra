package rtcingress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/db"
	socks "golang.org/x/net/proxy"
)

func TestGatewayIsolationAndAccounting(t *testing.T) {
	g := NewGateway(func(ctx context.Context, owner, addr string, probe bool) (net.Conn, error) {
		a, b := net.Pipe()
		go func() { defer func() { _ = b.Close() }(); _, _ = io.Copy(b, b) }()
		return a, nil
	}, func(context.Context, string) bool { return true })
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	go g.Serve(l)
	defer g.Close()
	g.Grant("owner-a", "a", "password-a", false)
	g.Grant("owner-b", "b", "password-b", false)
	connect := func(user, pass string) (net.Conn, error) {
		d, e := socks.SOCKS5("tcp", l.Addr().String(), &socks.Auth{User: user, Password: pass}, &net.Dialer{Timeout: time.Second})
		if e != nil {
			return nil, e
		}
		return d.Dial("tcp", "example.test:443")
	}
	if c, e := connect("a", "bad"); e == nil {
		_ = c.Close()
		t.Fatal("wrong password accepted")
	}
	a, e := connect("a", "password-a")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = a.Close() }()
	b, e := connect("b", "password-b")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = b.Close() }()
	echo := func(c net.Conn) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		if _, e := c.Write([]byte("payload")); e != nil {
			t.Fatal(e)
		}
		out := make([]byte, 7)
		if _, e := io.ReadFull(c, out); e != nil || string(out) != "payload" {
			t.Fatal("transfer failed", e)
		}
	}
	echo(a)
	echo(b)
	g.Revoke("owner-a")
	if _, e = a.Read(make([]byte, 1)); e == nil {
		t.Fatal("revoked stream remains open")
	}
	echo(b)
	if c, e := connect("a", "password-a"); e == nil {
		_ = c.Close()
		t.Fatal("revoked credential accepted")
	}
	// Synchronize stream closure before reading accounting.
	_ = b.Close()
	g.Close()
	g.mu.Lock()
	var up, down int64
	for k, u := range g.usage {
		if k.Owner == "owner-b" {
			up += u.Up
			down += u.Down
		}
	}
	g.mu.Unlock()
	if up != 14 || down != 14 {
		t.Fatalf("payload accounting %d/%d", up, down)
	}
	sink := &usageSink{fail: true}
	if g.Flush(context.Background(), sink) == nil {
		t.Fatal("expected database failure")
	}
	sink.fail = false
	if e = g.Flush(context.Background(), sink); e != nil {
		t.Fatal(e)
	}
	first := sink.total()
	_ = g.Flush(context.Background(), sink)
	if sink.total() != first {
		t.Fatal("retry double counted")
	}
}

type usageSink struct {
	mu   sync.Mutex
	fail bool
	rows map[string]db.RTCUsage
}

func (s *usageSink) SaveUsage(_ context.Context, owner, epoch string, u db.RTCUsage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rows == nil {
		s.rows = map[string]db.RTCUsage{}
	}
	key := owner + epoch + u.Hour.String()
	old := s.rows[key]
	u.Up = max(old.Up, u.Up)
	u.Down = max(old.Down, u.Down)
	s.rows[key] = u
	if s.fail {
		return errors.New("uncertain commit")
	}
	return nil
}
func (s *usageSink) total() int64 {
	var n int64
	for _, u := range s.rows {
		n += u.Up + u.Down
	}
	return n
}

func TestTenAccessesPayload(t *testing.T) {
	g := NewGateway(func(context.Context, string, string, bool) (net.Conn, error) {
		a, b := net.Pipe()
		go func() { defer func() { _ = b.Close() }(); _, _ = io.Copy(b, b) }()
		return a, nil
	}, func(context.Context, string) bool { return true })
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	go g.Serve(l)
	defer g.Close()
	var wg sync.WaitGroup
	for i := range 10 {
		user := fmt.Sprintf("synthetic-%d", i)
		g.Grant(user, user, "pass", false)
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, e := socks.SOCKS5("tcp", l.Addr().String(), &socks.Auth{User: user, Password: "pass"}, netDialer())
			if e != nil {
				t.Error(e)
				return
			}
			c, e := d.Dial("tcp", "example.test:443")
			if e != nil {
				t.Error(e)
				return
			}
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			payload := make([]byte, 32768)
			for range 32 {
				if _, e = c.Write(payload); e != nil {
					t.Error(e)
					return
				}
				if _, e = io.ReadFull(c, payload); e != nil {
					t.Error(e)
					return
				}
			}
		}()
	}
	wg.Wait()
	g.Close()
	g.mu.Lock()
	defer g.mu.Unlock()
	var up, down int64
	for _, u := range g.usage {
		up += u.Up
		down += u.Down
	}
	if up != 10*1048576 || down != up {
		t.Fatal("load counters", up, down)
	}
}
func netDialer() *net.Dialer { return &net.Dialer{Timeout: time.Second} }
