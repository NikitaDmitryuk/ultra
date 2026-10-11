package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
