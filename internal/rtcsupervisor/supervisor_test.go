package rtcsupervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/rtc"
	"github.com/google/uuid"
)

func TestSupervisorBoundedSessionsAndStop(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "transport")
	if e := os.WriteFile(binary, []byte("#!/bin/sh\nexec /bin/sleep 600\n"), 0700); e != nil {
		t.Fatal(e)
	}
	s := &Supervisor{Binary: binary, Directory: dir, GatewayPort: 12001, Content: &rtc.PrivateContent{MaxAccesses: 10, ProbeURL: "https://probe.example/bytes", BootstrapDNS: "192.0.2.53:53"}}
	h := s.Handler()
	sync := func(v []Session) int {
		b, _ := json.Marshal(v)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("PUT", "/sessions", bytes.NewReader(b)))
		return w.Code
	}
	sessions := []Session{}
	for range 11 {
		id := uuid.NewString()
		sessions = append(sessions, Session{Generation: id, Provider: "wbstream", Room: "synthetic-room", Key: strings.Repeat("a", 64), Username: id, Password: strings.Repeat("b", 64)})
	}
	if sync(sessions) != 400 {
		t.Fatal("capacity not enforced")
	}
	if sync(sessions[:10]) != 200 {
		t.Fatal("sessions rejected")
	}
	time.Sleep(100 * time.Millisecond)
	if sync(nil) != 200 {
		t.Fatal("stop failed")
	}
	if len(s.children) != 0 {
		t.Fatal("children retained")
	}
	for _, v := range sessions[:10] {
		if _, e := os.Stat(filepath.Join(dir, v.Generation)); !os.IsNotExist(e) {
			t.Fatal("runtime secret files retained")
		}
	}
	// A lost relay lease removes all sessions, not just the gateway registry.
	if sync(sessions[:1]) != 200 {
		t.Fatal("restart failed")
	}
	s.mu.Lock()
	s.lastSync = time.Now().Add(-61 * time.Second)
	s.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Watch(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		n := len(s.children)
		s.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("lease expiry did not stop children")
}
func TestCommandEnvironmentAndPrivateFiles(t *testing.T) {
	dir := t.TempDir()
	s := &Supervisor{Binary: "/bin/false", Directory: dir, Content: &rtc.PrivateContent{BootstrapDNS: "192.0.2.53:53"}, GatewayPort: 12001}
	v := Session{Generation: uuid.NewString(), Provider: "wbstream", Room: "synthetic", Key: strings.Repeat("a", 64), Username: "credential", Password: strings.Repeat("b", 64)}
	cmd, e := s.command(context.Background(), v, dir, false, 0)
	if e != nil {
		t.Fatal(e)
	}
	if len(cmd.Env) != 3 || strings.Contains(strings.Join(cmd.Env, "\n"), "TOKEN") {
		t.Fatal("unrestricted environment")
	}
	b, e := os.ReadFile(filepath.Join(dir, "server.json"))
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(b), v.Password) || cmd.Stdout != nil || cmd.Stderr != nil {
		t.Fatal("unsafe process configuration")
	}
	st, _ := os.Stat(filepath.Join(dir, "server.json"))
	if st.Mode().Perm() != 0600 {
		t.Fatal("runtime file permissions")
	}
}

func TestPinnedClientMode(t *testing.T) {
	dir := t.TempDir()
	s := &Supervisor{Binary: "/bin/false", Directory: dir, Content: &rtc.PrivateContent{}}
	_, e := s.command(context.Background(), Session{}, dir, true, 12345)
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(dir, "client.json"))
	if e != nil {
		t.Fatal(e)
	}
	var c struct {
		Mode  string `json:"mode"`
		SOCKS struct {
			Port int `json:"port"`
		} `json:"socks"`
	}
	if json.Unmarshal(b, &c) != nil || c.Mode != "cnc" || c.SOCKS.Port != 12345 {
		t.Fatal("pinned upstream client contract changed")
	}
}
