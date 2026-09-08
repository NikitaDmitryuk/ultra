package main

import (
	"encoding/json"
	"github.com/NikitaDmitryuk/ultra/internal/proxy"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestLoopbackProxies(t *testing.T) {
	data := []byte(`{"outbounds":[{"protocol":"freedom"}]}`)
	if _, err := render(data, "fast_tcp_reality", "0.0.0.0:10808", "127.0.0.1:10809"); err == nil {
		t.Fatal("public proxy allowed")
	}
	got, err := render(data, "fast_tcp_reality", "127.0.0.1:10808", "127.0.0.1:10809")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal(got, &doc)
	if len(doc["inbounds"].([]any)) != 2 {
		t.Fatal("missing local proxy")
	}
}

func TestBothLocalProxiesTransfer(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("through proxy")) }))
	defer target.Close()
	address := func() string {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		a := l.Addr().String()
		_ = l.Close()
		return a
	}
	socks, httpAddr := address(), address()
	data, err := render([]byte(`{"outbounds":[{"protocol":"freedom"}]}`), "fast_tcp_reality", socks, httpAddr)
	if err != nil {
		t.Fatal(err)
	}
	var runner proxy.Runner
	if err := runner.StartJSON(data); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = runner.Close() }()
	for _, addr := range []string{socks, httpAddr} {
		deadline := time.Now().Add(time.Second)
		for {
			c, e := net.DialTimeout("tcp", addr, 50*time.Millisecond)
			if e == nil {
				_ = c.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatal(e)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	for _, address := range []string{"socks5h://" + socks, "http://" + httpAddr} {
		tr := target.Client().Transport.(*http.Transport).Clone()
		u, _ := url.Parse(address)
		tr.Proxy = http.ProxyURL(u)
		client := &http.Client{Transport: tr, Timeout: time.Second}
		resp, err := client.Get(target.URL)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		tr.CloseIdleConnections()
		if err != nil || string(data) != "through proxy" {
			t.Fatal(err, string(data))
		}
	}
}
