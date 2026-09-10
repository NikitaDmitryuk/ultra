package main

import (
	"context"
	"flag"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/rtc"
	"github.com/NikitaDmitryuk/ultra/internal/rtcsupervisor"
)

type checkedListener struct {
	*net.UnixListener
	uid int
}

func (l checkedListener) Accept() (net.Conn, error) {
	for {
		c, e := l.AcceptUnix()
		if e != nil {
			return nil, e
		}
		if rtcsupervisor.PeerAllowed(c, l.uid) {
			return c, nil
		}
		_ = c.Close()
	}
}
func main() {
	socket := flag.String("socket", "/run/ultra-rtc/control.sock", "private control socket")
	content := flag.String("content", "", "private configuration")
	binary := flag.String("binary", "/usr/local/bin/olcrtc", "pinned transport binary")
	dir := flag.String("runtime", "/run/ultra-rtc", "private runtime directory")
	uid := flag.Int("relay-uid", -1, "authorized relay UID")
	port := flag.Int("gateway-port", 12001, "loopback gateway port")
	flag.Parse()
	cfg, e := rtc.LoadContent(*content)
	if e != nil || *uid < 0 {
		os.Exit(1)
	}
	if os.MkdirAll(filepath.Join(*dir, "names"), 0700) != nil {
		os.Exit(1)
	}
	for file, text := range map[string]string{"names": "UltraRTC\n", "surnames": "Bridge\n"} {
		if os.WriteFile(filepath.Join(*dir, "names", file), []byte(text), 0600) != nil {
			os.Exit(1)
		}
	}
	_ = os.Remove(*socket)
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: *socket, Net: "unix"})
	if e != nil {
		os.Exit(1)
	}
	if os.Chmod(*socket, 0660) != nil {
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()
	s := &rtcsupervisor.Supervisor{Binary: *binary, Directory: *dir, GatewayPort: *port, Content: cfg}
	server := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second}
	done := make(chan struct{})
	go func() { s.Watch(ctx); close(done) }()
	go func() { <-ctx.Done(); _ = server.Close() }()
	_ = server.Serve(checkedListener{l, *uid})
	cancel()
	<-done
}
