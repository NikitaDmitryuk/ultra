package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestBotMainHelper(t *testing.T) {
	if os.Getenv("ULTRA_TEST_BOT_MAIN") != "1" {
		return
	}
	os.Args = []string{"ultra-bot", "-dev", "-port", os.Getenv("ULTRA_TEST_BOT_PORT"), "-data-dir", os.Getenv("ULTRA_TEST_BOT_DATA"), "-admin-api-url", "http://127.0.0.1:1"}
	main()
}
func TestRequiredListenerFailureExitsEvenWhenDependenciesOffline(t *testing.T) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestBotMainHelper$")
	cmd.Dir = t.TempDir()
	cmd.Env = []string{"ULTRA_TEST_BOT_MAIN=1", "ULTRA_TEST_BOT_PORT=" + port, "ULTRA_TEST_BOT_DATA=" + t.TempDir(), "TELEGRAM_BOT_TOKEN=test-only", "ULTRA_RELAY_ADMIN_TOKEN=test-only", "ULTRA_DB_DSN=postgres://test:test@127.0.0.1:1/test?sslmode=disable", "ULTRA_BOT_TELEGRAM_SOCKS5=127.0.0.1:1"}
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "required HTTP listener failed") {
		t.Fatalf("listener failure not propagated: %v %s", err, output)
	}
}

func TestHTTPAndCachedSubscriptionSurviveOfflineDependenciesAndShutdown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	_ = listener.Close()
	if err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	digest := sha256.Sum256([]byte(token))
	key := hex.EncodeToString(digest[:]) + "?"
	data, err := json.Marshal(map[string]any{"version": 1, "entries": map[string]any{key: map[string]any{"body": []byte("vless://cached\n"), "headers": map[string]string{"Content-Type": "text/plain"}, "confirmed_at": time.Now()}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dataDir, "subscriptions.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBotMainHelper$")
	cmd.Dir = t.TempDir()
	cmd.Env = []string{"ULTRA_TEST_BOT_MAIN=1", "ULTRA_TEST_BOT_PORT=" + port, "ULTRA_TEST_BOT_DATA=" + dataDir, "TELEGRAM_BOT_TOKEN=test-only", "ULTRA_RELAY_ADMIN_TOKEN=test-only", "ULTRA_DB_DSN=postgres://test:test@127.0.0.1:1/test?sslmode=disable", "ULTRA_BOT_TELEGRAM_SOCKS5=127.0.0.1:1"}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	base := "http://127.0.0.1:" + port
	deadline := time.Now().Add(3 * time.Second)
	for {
		response, e := client.Get(base + "/healthz")
		if e == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("HTTP startup waited for Telegram or PostgreSQL")
		}
		time.Sleep(10 * time.Millisecond)
	}
	response, err := client.Get(base + "/happ")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("import page unavailable: %d", response.StatusCode)
	}
	request, err := http.NewRequest("GET", base+"/sub/"+token, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Forwarded-Proto", "https")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 200 || string(body) != "vless://cached\n" || response.Header.Get("X-Ultra-State") != "cached" {
		t.Fatalf("cache unavailable offline: %d %q %v", response.StatusCode, body, err)
	}
	transport.CloseIdleConnections()
	started := time.Now()
	if err = cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	waited = true
	if err != nil || time.Since(started) > 12*time.Second {
		t.Fatalf("offline workers prevented graceful shutdown: %v", err)
	}
}
