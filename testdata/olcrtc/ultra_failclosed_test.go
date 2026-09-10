package server

import (
	"net"
	"testing"
	"time"
)

func TestUltraUpstreamFailuresNeverDialDestination(t *testing.T) {
	target, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	req := ConnectRequest{Addr: "127.0.0.1", Port: target.Addr().(*net.TCPAddr).Port}
	upstream, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := upstream.Addr().(*net.TCPAddr).Port
	_ = upstream.Close()
	s := &Server{socksProxyAddr: "127.0.0.1", socksProxyPort: port}
	if conn, e := s.dial(req); e == nil {
		conn.Close()
		t.Fatal("refused upstream accepted")
	}
	upstream, e = net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer upstream.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := upstream.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		b := make([]byte, 3)
		_, _ = c.Read(b)
		_, _ = c.Write([]byte{5, 255})
	}()
	s.socksProxyPort = upstream.Addr().(*net.TCPAddr).Port
	s.socksProxyUser = "user"
	s.socksProxyPass = "wrong"
	if conn, e := s.dial(req); e == nil {
		conn.Close()
		t.Fatal("rejected authentication accepted")
	}
	<-done
	_ = target.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond))
	if conn, e := target.Accept(); e == nil {
		conn.Close()
		t.Fatal("destination reached directly")
	}
}
