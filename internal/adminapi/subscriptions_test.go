package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/config"
)

type testSubscriptions struct{ token string }

func (s *testSubscriptions) Rotate(context.Context, string) (string, error) {
	s.token = "issued"
	return s.token, nil
}
func (s *testSubscriptions) Revoke(context.Context, string) error { s.token = ""; return nil }
func (s *testSubscriptions) Resolve(_ context.Context, token string) (string, error) {
	if token == s.token && token != "" {
		return "u1", nil
	}
	return "", pgx.ErrNoRows
}
func TestSubscriptionHTTP(t *testing.T) {
	users := newFakeUserManager()
	spec := &config.Spec{Role: config.RoleBridge, DevMode: true, PublicHost: "localhost", VLESSPort: 443}
	s, err := NewServer("127.0.0.1:0", "secret", users, nil, spec, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.Subscriptions = &testSubscriptions{}
	request := func(method, path string, auth bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		if auth {
			r.Header.Set("Authorization", "Bearer secret")
		}
		w := httptest.NewRecorder()
		s.authMiddleware(s.mux).ServeHTTP(w, r)
		return w
	}
	if w := request("POST", "/v1/users/u1/subscription", false); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request("POST", "/v1/users/u1/subscription", true); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := request("GET", "/v1/subscriptions/issued", true); w.Code != 200 || !strings.Contains(w.Body.String(), "vless://u1@localhost") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, test := range []struct {
		format, ua string
		json       bool
		status     int
	}{
		{"", "Happ/3 Android", false, 200}, {"happ", "other", true, 200}, {"happ", "Happ/3 Android", true, 200}, {"uri", "Happ/3 Android", false, 200}, {"", "other", false, 200}, {"bad", "", false, 400},
	} {
		r := httptest.NewRequest("GET", "/v1/subscriptions/issued?format="+test.format, nil)
		r.Header.Set("Authorization", "Bearer secret")
		r.Header.Set("User-Agent", test.ua)
		w := httptest.NewRecorder()
		s.authMiddleware(s.mux).ServeHTTP(w, r)
		if w.Code != test.status {
			t.Fatal(test, w.Code)
		}
		if w.Code != 200 {
			continue
		}
		if test.json {
			var profiles []map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &profiles); err != nil || len(profiles) != 1 || profiles[0]["remarks"] != automaticProfileName || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
				t.Fatal("bad JSON export", err)
			}
			meta, ok := profiles[0]["meta"].(map[string]any)
			if !ok || meta["serverDescription"] != automaticProfileDescription {
				t.Fatal("missing Happ server description", profiles[0]["meta"])
			}
		} else if !strings.HasPrefix(w.Body.String(), "vless://") || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
			t.Fatal("URI compatibility lost")
		}
	}
	for _, query := range []string{"transport=unknown", "transport=xhttp-tls&format=happ"} {
		if w := request("GET", "/v1/subscriptions/issued?"+query, true); w.Code != 400 {
			t.Fatal("invalid transport accepted", w.Code)
		}
	}
	if w := request("GET", "/v1/subscriptions/issued?transport=xhttp-tls", true); w.Code != 503 {
		t.Fatal("absent listener exported", w.Code)
	}
	spec.DevMode = false
	spec.PublicXHTTPTLS = &config.PublicXHTTPTLSSpec{Port: 5443, ServerName: "vpn.example", Path: "/connect"}
	if w := request("GET", "/v1/subscriptions/issued?format=uri&transport=xhttp-tls", true); w.Code != 200 || !strings.Contains(w.Body.String(), "security=tls") || !strings.Contains(w.Body.String(), "vless://u1@localhost:5443") {
		t.Fatal("TLS subscription failed", w.Code)
	}
	u := users.users["u1"]
	u.IsActive = false
	users.users["u1"] = u
	if w := request("GET", "/v1/subscriptions/issued", true); w.Code != 404 {
		t.Fatal("disabled", w.Code)
	}
	u.IsActive = true
	users.users["u1"] = u
	if w := request("DELETE", "/v1/users/u1/subscription", true); w.Code != http.StatusNoContent {
		t.Fatal(w.Code)
	}
	if w := request("GET", "/v1/subscriptions/issued", true); w.Code != 404 {
		t.Fatal("revoked", w.Code)
	}
}

type adminSubscriptions struct {
	testSubscriptions
	allowed bool
	err     error
}

func (s *adminSubscriptions) IsAdminOwner(context.Context, string) (bool, error) {
	return s.allowed, s.err
}

func TestExperimentUsesOwnerPermissionsAndLiveDescriptor(t *testing.T) {
	users := newFakeUserManager()
	spec := &config.Spec{Role: config.RoleBridge, DevMode: true, PublicHost: "localhost", VLESSPort: 443}
	s, err := NewServer("127.0.0.1:0", "secret", users, nil, spec, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	permissions := &adminSubscriptions{testSubscriptions: testSubscriptions{token: "issued"}}
	s.Subscriptions = permissions
	file := filepath.Join(t.TempDir(), "experimental.json")
	spec.ExperimentalProfileFile = file
	descriptor := config.ExperimentalProfile{Host: "experiment.example", StatusPort: 18082, Endpoint: config.PublicXHTTPTLSSpec{Port: 5543, ServerName: "site.example", Path: "/test"}}
	write := func() {
		raw, _ := json.Marshal(descriptor)
		if err := os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	request := func(query string) string {
		r := httptest.NewRequest("GET", "/v1/subscriptions/issued"+query, nil)
		r.Header.Set("Authorization", "Bearer secret")
		r.Header.Set("X-Admin", "true")
		w := httptest.NewRecorder()
		s.authMiddleware(s.mux).ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		return w.Body.String()
	}
	if strings.Contains(request("?admin=true"), "experiment.example") {
		t.Fatal("query bypass")
	}
	permissions.allowed = true
	if !strings.Contains(request(""), "experiment.example:5543") {
		t.Fatal("admin experiment missing")
	}
	descriptor.Endpoint.Port = 5544
	write()
	if !strings.Contains(request(""), "experiment.example:5544") {
		t.Fatal("descriptor cached")
	}
	permissions.allowed = false
	if strings.Contains(request(""), "experiment.example") {
		t.Fatal("removed admin retained profile")
	}
	permissions.allowed = true
	permissions.err = errors.New("unavailable")
	if strings.Contains(request(""), "experiment.example") {
		t.Fatal("permissions failed open")
	}
}

type cacheSubscriptions struct {
	testSubscriptions
	unavailable bool
}

func (s *cacheSubscriptions) ListActiveTokens(context.Context) ([]string, error) {
	if s.unavailable {
		return nil, errors.New("database unavailable")
	}
	if s.token == "" {
		return []string{}, nil
	}
	return []string{s.token}, nil
}
func TestCompleteSubscriptionCacheRequiresConfirmedSource(t *testing.T) {
	spec := &config.Spec{Role: config.RoleBridge, DevMode: true, PublicHost: "localhost", VLESSPort: 443}
	server, err := NewServer("127.0.0.1:0", "admin", newFakeUserManager(), nil, spec, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	source := &cacheSubscriptions{testSubscriptions: testSubscriptions{token: "cache-secret"}}
	server.Subscriptions = source
	request := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/v1/subscriptions/cache", nil)
		req.Header.Set("Authorization", "Bearer admin")
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, req)
		return w
	}
	w := request()
	if w.Code != 200 || strings.Contains(w.Body.String(), "cache-secret") {
		t.Fatal("cache incomplete or leaks token", w.Code)
	}
	var payload struct {
		Entries map[string]subscriptionCacheEntry `json:"entries"`
	}
	if json.Unmarshal(w.Body.Bytes(), &payload) != nil || len(payload.Entries) != 2 {
		t.Fatal("missing cached formats")
	}
	source.unavailable = true
	if w = request(); w.Code != 503 {
		t.Fatal("unconfirmed source extends cache", w.Code)
	}
	source.unavailable = false
	source.token = ""
	payload.Entries = nil
	w = request()
	if json.Unmarshal(w.Body.Bytes(), &payload) != nil || len(payload.Entries) != 0 {
		t.Fatal("revoked subscription retained")
	}
}

func TestSubscriptionDefaultAndRestrictedPreview(t *testing.T) {
	spec := &config.Spec{Role: config.RoleBridge, DevMode: true, PublicHost: "localhost", VLESSPort: 443, HappDefaultJSON: true,
		SubscriptionPreviewBridges: []config.SubscriptionBridge{{ID: "test", Host: "test.example", Port: 443, Security: "tls", Transport: "xhttp", ServerName: "test.example", Path: "/vpn", Fingerprint: "firefox"}}}
	server, err := NewServer("127.0.0.1:0", "secret", newFakeUserManager(), nil, spec, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	permissions := &adminSubscriptions{testSubscriptions: testSubscriptions{token: "issued"}}
	server.Subscriptions = permissions
	request := func(query, ua string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/v1/subscriptions/issued?"+query, nil)
		r.Header.Set("Authorization", "Bearer secret")
		r.Header.Set("User-Agent", ua)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		return w
	}
	if w := request("", "Happ/3 Android"); w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		t.Fatal("default not applied", w.Code)
	}
	if w := request("format=uri", "Happ/3"); !strings.HasPrefix(w.Body.String(), "vless://") || strings.Contains(w.Body.String(), "test.example") {
		t.Fatal("preview leaked")
	}
	if w := request("format=happ&preview=reserve", "Happ/3"); w.Code != 404 {
		t.Fatal("non-admin preview", w.Code)
	}
	if server.previewUACount.Load() != 0 {
		t.Fatal("unauthorised UA captured")
	}
	if w := request("format=happ&preview=reserve-test", "Happ/3"); w.Code != 404 {
		t.Fatal("unauthorised fault preview", w.Code)
	}
	permissions.allowed = true
	if w := request("format=happ&preview=reserve", "Happ/3"); w.Code != 200 || !strings.Contains(w.Body.String(), "test.example") || !strings.Contains(w.Body.String(), "firefox") {
		t.Fatal("admin preview missing", w.Code)
	}
	spec.SubscriptionPreviewBridges = append(spec.SubscriptionPreviewBridges, config.SubscriptionBridge{ID: "reserve", Host: "reserve.example", Port: 24443, Security: "reality", Transport: "tcp", PublicKey: strings.Repeat("A", 43), ServerName: "example.com", Fingerprint: "firefox"})
	if w := request("format=happ&preview=reserve-test", "Happ/3"); w.Code != 200 {
		t.Fatal("fault preview", w.Code)
	} else {
		var profiles []map[string]any
		if json.Unmarshal(w.Body.Bytes(), &profiles) != nil || len(profiles) != 4 {
			t.Fatal("missing scenarios")
		}
	}
	permissions.err = errors.New("offline")
	if w := request("format=happ&preview=reserve-test", "Happ/3"); w.Code != 503 {
		t.Fatal("fault permission failure allowed", w.Code)
	}
	if w := request("format=happ&preview=reserve", "Happ/3"); w.Code != 503 {
		t.Fatal("permission failure allowed", w.Code)
	}
}

func TestPreviewUserAgentCaptureBounded(t *testing.T) {
	var output bytes.Buffer
	server := &Server{log: slog.New(slog.NewJSONHandler(&output, nil))}
	for i := 0; i < 20; i++ {
		server.capturePreviewUserAgent("Happ/3 " + strings.Repeat("x", 1000) + "\ncontrol")
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 8 {
		t.Fatal("unbounded capture", len(lines))
	}
	for _, line := range lines {
		var record map[string]any
		if json.Unmarshal([]byte(line), &record) != nil || len(record["user_agent"].(string)) != 256 || len(record) != 4 {
			t.Fatal("unexpected diagnostic fields")
		}
	}
}
