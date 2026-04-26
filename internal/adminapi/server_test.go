package adminapi

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/config"
)

type fakeUserManager struct {
	users       map[string]auth.User
	renameCalls int
	enableCalls int
	rotateCalls int
	lastRename  struct {
		id   string
		name string
	}
}

func newFakeUserManager() *fakeUserManager {
	return &fakeUserManager{
		users: map[string]auth.User{
			"u1": {UUID: "u1", Name: "Alice", IsActive: true},
			"u2": {UUID: "u2", Name: "Bob", IsActive: false},
		},
	}
}

func (m *fakeUserManager) AddUser(name string) (auth.User, error) { return auth.User{}, nil }
func (m *fakeUserManager) RenameUser(id, name string) (auth.User, error) {
	m.renameCalls++
	m.lastRename.id = id
	m.lastRename.name = name
	u, ok := m.users[id]
	if !ok {
		return auth.User{}, auth.ErrUserNotFound
	}
	u.Name = name
	m.users[id] = u
	return u, nil
}
func (m *fakeUserManager) RemoveUser(id string) error { return nil }
func (m *fakeUserManager) EnableUser(id string) error {
	m.enableCalls++
	u, ok := m.users[id]
	if !ok {
		return auth.ErrUserNotFound
	}
	u.IsActive = true
	m.users[id] = u
	return nil
}
func (m *fakeUserManager) RotateUUID(id string) (string, error) {
	m.rotateCalls++
	u, ok := m.users[id]
	if !ok {
		return "", auth.ErrUserNotFound
	}
	delete(m.users, id)
	newID := id + "-rotated"
	u.UUID = newID
	m.users[newID] = u
	return newID, nil
}
func (m *fakeUserManager) List() []auth.User {
	var out []auth.User
	for _, u := range m.users {
		if u.IsActive {
			out = append(out, u)
		}
	}
	return out
}
func (m *fakeUserManager) ListAll() []auth.User {
	var out []auth.User
	for _, u := range m.users {
		out = append(out, u)
	}
	return out
}
func (m *fakeUserManager) Lookup(id string) (auth.User, bool) {
	u, ok := m.users[id]
	return u, ok
}
func (m *fakeUserManager) Close() {}

func newHTTPTestServer(t *testing.T, users auth.UserManager, spec *config.Spec) *httptest.Server {
	t.Helper()
	s, err := NewServer("127.0.0.1:0", "secret", users, nil, spec, slog.Default())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return httptest.NewServer(s.authMiddleware(s.mux))
}

func doAuthedJSON(
	t *testing.T,
	client *http.Client,
	method, url string,
	body any,
) (*http.Response, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer secret")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	respBody, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); cerr != nil {
		t.Fatalf("close body: %v", cerr)
	}
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, respBody
}

func TestPatchUserRequiresName(t *testing.T) {
	mgr := newFakeUserManager()
	spec := &config.Spec{Exit: config.ExitTunnelSpec{Address: "127.0.0.1", Port: 65535}}
	ts := newHTTPTestServer(t, mgr, spec)
	defer ts.Close()

	resp, body := doAuthedJSON(t, ts.Client(), http.MethodPatch, ts.URL+"/v1/users/u1", map[string]any{})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d, body=%s", resp.StatusCode, string(body))
	}
	if mgr.renameCalls != 0 {
		t.Fatalf("expected renameCalls=0, got %d", mgr.renameCalls)
	}
}

func TestEnableAndRotateEndpoints(t *testing.T) {
	mgr := newFakeUserManager()
	spec := &config.Spec{Exit: config.ExitTunnelSpec{Address: "127.0.0.1", Port: 65535}}
	ts := newHTTPTestServer(t, mgr, spec)
	defer ts.Close()

	resp, body := doAuthedJSON(t, ts.Client(), http.MethodPost, ts.URL+"/v1/users/u2/enable", map[string]any{})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("enable status: got %d, body=%s", resp.StatusCode, string(body))
	}
	if mgr.enableCalls != 1 {
		t.Fatalf("expected enableCalls=1, got %d", mgr.enableCalls)
	}

	resp, body = doAuthedJSON(t, ts.Client(), http.MethodPost, ts.URL+"/v1/users/u2/rotate", map[string]any{})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotate status: got %d, body=%s", resp.StatusCode, string(body))
	}
	var out map[string]string
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode rotate response: %v", err)
	}
	if out["uuid"] == "" {
		t.Fatalf("expected non-empty uuid in rotate response")
	}
	if mgr.rotateCalls != 1 {
		t.Fatalf("expected rotateCalls=1, got %d", mgr.rotateCalls)
	}
}

func TestHealthEndpointRespondsJSON(t *testing.T) {
	mgr := newFakeUserManager()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	spec := &config.Spec{Exit: config.ExitTunnelSpec{Address: "127.0.0.1", Port: port}}
	ts := newHTTPTestServer(t, mgr, spec)
	defer ts.Close()

	resp, body := doAuthedJSON(t, ts.Client(), http.MethodGet, ts.URL+"/v1/health", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, body=%s", resp.StatusCode, string(body))
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	bridge, ok := out["bridge"].(map[string]any)
	if !ok {
		t.Fatalf("expected bridge object, got %#v", out["bridge"])
	}
	if _, ok := bridge["reachable"]; !ok {
		t.Fatalf("expected bridge.reachable field")
	}
	exit, ok := out["exit"].(map[string]any)
	if !ok {
		t.Fatalf("expected exit object, got %#v", out["exit"])
	}
	if _, ok := exit["reachable"]; !ok {
		t.Fatalf("expected exit.reachable field")
	}
}
