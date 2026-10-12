package adminapi

import (
	"context"
	"encoding/json"
	"errors"
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
	return "", errors.New("not found")
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
			if err := json.Unmarshal(w.Body.Bytes(), &profiles); err != nil || len(profiles) != 1 || profiles[0]["remarks"] != "Автоматически" || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
				t.Fatal("bad JSON export", err)
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
