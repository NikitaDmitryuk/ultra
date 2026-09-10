package rtcsupervisor

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/rtc"
	"github.com/google/uuid"
)

type child struct {
	statusMu sync.Mutex
	s        Session
	cancel   context.CancelFunc
	done     chan struct{}
	status   Status
}
type Supervisor struct {
	mu                sync.Mutex
	children          map[string]*child
	lastSync          time.Time
	probe             chan struct{}
	Binary, Directory string
	GatewayPort       int
	Content           *rtc.PrivateContent
}

func (s *Supervisor) Handler() http.Handler {
	s.children = map[string]*child{}
	s.lastSync = time.Now()
	s.probe = make(chan struct{}, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /sessions", s.syncHTTP)
	return mux
}
func (s *Supervisor) syncHTTP(w http.ResponseWriter, r *http.Request) {
	var desired []Session
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	if json.NewDecoder(r.Body).Decode(&desired) != nil || len(desired) > s.Content.MaxAccesses {
		http.Error(w, "invalid", 400)
		return
	}
	ids := map[string]Session{}
	for _, v := range desired {
		_, e := uuid.Parse(v.Generation)
		key, ke := hex.DecodeString(v.Key)
		pass, pe := hex.DecodeString(v.Password)
		if e != nil || ke != nil || len(key) != 32 || pe != nil || len(pass) != 32 || v.Username != v.Generation || len(v.Room) > 160 || (v.Provider != "telemost" && v.Provider != "wbstream") {
			http.Error(w, "invalid", 400)
			return
		}
		if _, ok := ids[v.Generation]; ok {
			http.Error(w, "invalid", 400)
			return
		}
		ids[v.Generation] = v
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastSync = time.Now()
	for id, c := range s.children {
		if v, ok := ids[id]; !ok || v != c.s {
			c.cancel()
			<-c.done
			delete(s.children, id)
		}
	}
	for id, v := range ids {
		if _, ok := s.children[id]; !ok {
			ctx, cancel := context.WithCancel(context.Background())
			c := &child{s: v, cancel: cancel, done: make(chan struct{}), status: Status{Generation: id}}
			s.children[id] = c
			go s.run(ctx, c)
		}
	}
	out := []Status{}
	for _, c := range s.children {
		c.statusMu.Lock()
		out = append(out, c.status)
		c.statusMu.Unlock()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
func (s *Supervisor) Watch(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.stop()
			return
		case <-t.C:
			s.mu.Lock()
			expired := time.Since(s.lastSync) > 60*time.Second
			s.mu.Unlock()
			if expired {
				s.stop()
			}
		}
	}
}

// Cancellation never needs the supervisor mutex, so waiting while removing a child is safe.
func (s *Supervisor) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, c := range s.children {
		c.cancel()
		<-c.done
		delete(s.children, id)
	}
}
func (s *Supervisor) publish(ctx context.Context, c *child, st Status) {
	c.statusMu.Lock()
	defer c.statusMu.Unlock()
	if ctx.Err() == nil {
		c.status = st
	}
}
func (s *Supervisor) run(ctx context.Context, c *child) {
	defer close(c.done)
	// Child status has its own lock, independent of session removal.
	publish := func(st Status) { s.publish(ctx, c, st) }
	dir := filepath.Join(s.Directory, c.s.Generation)
	if os.MkdirAll(dir, 0700) != nil {
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if os.WriteFile(filepath.Join(dir, "key"), []byte(c.s.Key), 0600) != nil {
		return
	}
	delays := []time.Duration{5 * time.Second, 15 * time.Second, 60 * time.Second, 300 * time.Second}
	attempt := 0
	for ctx.Err() == nil {
		st := Status{Generation: c.s.Generation}
		cmd, e := s.command(ctx, c.s, dir, false, 0)
		if e == nil {
			e = cmd.Start()
		}
		if e != nil {
			st.Error = "transport_start_failed"
			publish(st)
			return
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		st.Running = true
		publish(st)
		select {
		case s.probe <- struct{}{}:
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			<-done
			return
		}
		checked := s.check(ctx, c.s, dir)
		<-s.probe
		if checked {
			now := time.Now().UTC()
			st.Ready = true
			st.Checked = &now
			attempt = 0
		} else {
			st.Error = "room_check_failed"
		}
		publish(st)
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			<-done
			return
		case <-done:
		}
		st.Running = false
		st.Ready = false
		st.Error = "transport_disconnected"
		publish(st)
		delay := delays[min(attempt, len(delays)-1)]
		attempt++
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (s *Supervisor) command(ctx context.Context, v Session, dir string, client bool, port int) (*exec.Cmd, error) {
	mode := "srv"
	file := "server.json"
	socks := map[string]any{"proxy_addr": "127.0.0.1", "proxy_port": s.GatewayPort, "proxy_user": v.Username, "proxy_pass": v.Password}
	if client {
		mode = "cnc"
		file = "client.json"
		socks = map[string]any{"host": "127.0.0.1", "port": port, "user": v.Username, "pass": v.Password}
	}
	cfg := map[string]any{"mode": mode, "data": filepath.Join(s.Directory, "names"), "auth": map[string]any{"provider": v.Provider}, "room": map[string]any{"id": v.Room}, "crypto": map[string]any{"key_file": filepath.Join(dir, "key")}, "net": map[string]any{"transport": "vp8channel", "dns": s.Content.BootstrapDNS}, "socks": socks, "vp8": map[string]any{"fps": 30, "batch_size": 64}, "liveness": map[string]any{"interval": "10s", "timeout": "15s", "failures": 4}, "debug": false}
	b, e := json.Marshal(cfg)
	if e != nil {
		return nil, e
	}
	path := filepath.Join(dir, file)
	if e = os.WriteFile(path, b, 0600); e != nil {
		return nil, e
	}
	cmd := exec.CommandContext(ctx, s.Binary, path)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "TMPDIR=" + dir}
	cmd.WaitDelay = 5 * time.Second
	return cmd, nil
}
func (s *Supervisor) check(parent context.Context, v Session, dir string) bool {
	ctx, cancel := context.WithTimeout(parent, 120*time.Second)
	defer cancel()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return false
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	cmd, e := s.command(ctx, v, dir, true, port)
	if e != nil || cmd.Start() != nil {
		return false
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	proxyURL := &url.URL{Scheme: "socks5", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), User: url.UserPassword(v.Username, v.Password)}
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect denied") }}
	for ctx.Err() == nil {
		req, e := http.NewRequestWithContext(ctx, "GET", s.Content.ProbeURL, nil)
		if e != nil {
			return false
		}
		resp, e := client.Do(req)
		if e == nil {
			n, re := io.Copy(io.Discard, io.LimitReader(resp.Body, 65537))
			_ = resp.Body.Close()
			if resp.StatusCode == 200 && re == nil && n == 65536 {
				return true
			}
		}
		timer := time.NewTimer(3 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}
	}
	return false
}
