package proxy

import (
	"context"
	"fmt"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"io"
	"net"
	"testing"
	"time"
)

func TestReloadTerminatesEstablishedTransfer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			go func() { defer func() { _ = c.Close() }(); _, _ = io.Copy(c, c) }()
		}
	}()
	var r Runner
	config := func(tag string) []byte {
		return []byte(fmt.Sprintf(`{"outbounds":[{"protocol":"freedom","tag":%q}]}`, tag))
	}
	if err = r.StartJSON(config("before")); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	destination := xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(listener.Addr().(*net.TCPAddr).Port))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := core.Dial(ctx, r.Instance(), destination)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	exchange := func() error {
		if _, e := conn.Write([]byte("x")); e != nil {
			return e
		}
		_, e := io.ReadFull(conn, make([]byte, 1))
		return e
	}
	if err = exchange(); err != nil {
		t.Fatal(err)
	}
	if err = r.Reload(config("after")); err != nil {
		t.Fatal(err)
	}
	if err = exchange(); err == nil {
		t.Fatal("old transfer survives successful reload")
	}
	fresh, err := core.Dial(ctx, r.Instance(), destination)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fresh.Close() }()
	if _, err = fresh.Write([]byte("y")); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(fresh, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
}
