package bot

import (
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicSubscriptionProxy(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer admin-secret" || r.URL.Path != "/v1/subscriptions/"+token {
			t.Error("wrong upstream auth or route")
		}
		w.Header().Set("profile-update-interval", "1")
		_, _ = w.Write([]byte("vless://test@localhost:443\n"))
	}))
	defer upstream.Close()
	b := &Bot{adminAPIURL: upstream.URL, adminAPIToken: "admin-secret"}
	mux := http.NewServeMux()
	b.registerMiniAppRoutes(mux)
	for _, part := range []string{"invalid", token} {
		r := httptest.NewRequest("GET", "/sub/"+part, nil)
		r.TLS = &tls.ConnectionState{}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if part == token {
			if w.Code != 200 || !strings.HasPrefix(w.Body.String(), "vless://") || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal(w.Code)
			}
		} else if w.Code != 404 {
			t.Fatal(w.Code)
		}
	}
	plain := httptest.NewRecorder()
	mux.ServeHTTP(plain, httptest.NewRequest("GET", "/sub/"+token, nil))
	if plain.Code != http.StatusUpgradeRequired {
		t.Fatal("plaintext subscription allowed")
	}
	if calls != 1 {
		t.Fatal("invalid token reached upstream")
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("POST", "/api/users/test/subscription", nil))
	if w.Code != 401 {
		t.Fatal("unauthenticated rotation", w.Code)
	}
}

func TestHappImportPage(t *testing.T) {
	b := &Bot{}
	mux := http.NewServeMux()
	b.registerMiniAppRoutes(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/happ", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `id="launch-happ"`) {
		t.Fatal("import page unavailable", w.Code)
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("import page leaks navigation state")
	}
	if strings.Contains(w.Body.String(), "telegram-web-app.js") {
		t.Fatal("browser import must not depend on Telegram WebView")
	}
}

func TestPublicSubscriptionForwardsFormat(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.UserAgent() != "Happ/3 Android" || r.URL.Query().Get("format") != "happ" || r.URL.Query().Has("ignored") {
			t.Error("missing format or UA, or forwarded arbitrary query")
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Vary", "User-Agent")
		_, _ = w.Write([]byte(`[{"remarks":"Автоматически"}]`))
	}))
	defer upstream.Close()
	b := &Bot{adminAPIURL: upstream.URL, adminAPIToken: "secret"}
	mux := http.NewServeMux()
	b.registerMiniAppRoutes(mux)
	r := httptest.NewRequest("GET", "/sub/"+token+"?format=happ&ignored=secret", nil)
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("User-Agent", "Happ/3 Android")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/json; charset=utf-8" || w.Header().Get("Vary") != "User-Agent" || !strings.HasPrefix(w.Body.String(), "[") {
		t.Fatal("lost JSON response", w.Code)
	}
}

func TestPublicSubscriptionForwardsTransport(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("format") != "uri" || r.URL.Query().Get("transport") != "xhttp-tls" || r.URL.Query().Has("ignored") || r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("lost transport or authorization, or forwarded arbitrary query")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("vless://test"))
	}))
	defer upstream.Close()
	b := &Bot{adminAPIURL: upstream.URL, adminAPIToken: "secret"}
	mux := http.NewServeMux()
	b.registerMiniAppRoutes(mux)
	r := httptest.NewRequest("GET", "/sub/"+token+"?format=uri&transport=xhttp-tls&ignored=secret", nil)
	r.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "vless://test" || w.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatal("lost URI response", w.Code)
	}
}
