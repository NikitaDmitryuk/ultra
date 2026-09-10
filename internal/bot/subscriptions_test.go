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

func TestPublicRTCSubscriptionFormat(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "format=olcrtc" {
			t.Error("RTC format lost or arbitrary query forwarded")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("olcrtc://test\n"))
	}))
	defer upstream.Close()
	b := &Bot{adminAPIURL: upstream.URL, adminAPIToken: "secret"}
	mux := http.NewServeMux()
	b.registerMiniAppRoutes(mux)
	r := httptest.NewRequest("GET", "/sub/"+token+"?format=olcrtc&ignored=secret", nil)
	r.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "olcrtc://test\n" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w.Code)
	}
}

func TestRTCImportPage(t *testing.T) {
	b := &Bot{}
	mux := http.NewServeMux()
	b.registerMiniAppRoutes(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/rtc-import", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `id="launch-client"`) {
		t.Fatal("import page unavailable", w.Code)
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("import page leaks navigation state")
	}
	if strings.Contains(w.Body.String(), "telegram-web-app.js") {
		t.Fatal("browser import must not depend on Telegram WebView")
	}
}
