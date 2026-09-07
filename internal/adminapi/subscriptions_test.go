package adminapi

import (
	"context"
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
