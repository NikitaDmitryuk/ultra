package proxy

import (
	"context"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFullBodyProbe(t *testing.T) {
	for _, size := range []int{16384, 65536, 65537} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(strings.Repeat("x", size))) }))
		result := checkBody(context.Background(), server.Client(), server.URL)
		if result.OK != (size == 65536) {
			t.Fatalf("size %d: %+v", size, result)
		}
		if checkBody(context.Background(), http.DefaultClient, server.URL).OK {
			t.Fatal("accepted untrusted cert")
		}
		server.Close()
	}
}
func TestProbeStallDeadline(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 16384)))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result := checkBody(ctx, server.Client(), server.URL)
	if result.OK || result.Bytes != 16384 || result.DurationMS > 1000 {
		t.Fatalf("stall: %+v", result)
	}
}

func TestProbeUsesExactTagWithoutDirectFallback(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(strings.Repeat("x", 65536)))
	}))
	defer server.Close()
	var runner Runner
	if err := runner.StartJSON([]byte(`{"log":{"loglevel":"error"},"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"to-exit-good","protocol":"freedom"},{"tag":"to-exit-bad","protocol":"blackhole"}]}`)); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = runner.Close() }()
	addr := server.Listener.Addr().(*net.TCPAddr)
	for _, id := range []string{"good", "bad", "missing"} {
		before := requests.Load()
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		h := runner.ProbeExit(ctx, exits.Node{ID: id, Address: "127.0.0.1", Port: addr.Port}, []string{server.URL})
		cancel()
		if h.InternetOK != (id == "good") {
			t.Fatal(id, h)
		}
		if id != "good" && requests.Load() != before {
			t.Fatal("direct fallback for", id)
		}
	}
}
