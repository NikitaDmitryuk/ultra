package bot

import (
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/subscriptionmeta"
)

func TestSubscriptionQuotaProxyAndStaleCache(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	confirmed := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	metadata := map[string]string{
		"subscription-userinfo": "upload=0; download=400; total=1000",
		"announce":              "base64:" + base64.StdEncoding.EncodeToString([]byte("Общая квота выходов; остальные выходы отдельно.")),
		"X-Ultra-Quota-Scope":   "shared", "X-Ultra-Quota-State": "ready", "X-Ultra-Quota-Period": "2026-10",
		"X-Ultra-Quota-Observed-At": "2026-10-12T13:00:00Z", "X-Ultra-Quota-Resets-At": "2026-11-01T00:00:00Z",
	}
	broken := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for key, value := range metadata {
			w.Header().Set(key, value)
		}
		if broken {
			w.Header().Set("subscription-userinfo", "upload=0; download=0; total=999999")
			w.Header().Set("X-Ultra-Quota-Observed-At", "2099-01-01T00:00:00Z")
			w.Header().Set("Content-Length", "1000")
		}
		_, _ = w.Write([]byte("vless://confirmed"))
	}))
	defer upstream.Close()
	b := &Bot{adminAPIURL: upstream.URL}
	if err := b.ConfigureSubscriptionCache(filepath.Join(t.TempDir(), "cache.json")); err != nil {
		t.Fatal(err)
	}
	entries := map[string]cachedSubscription{}
	for _, format := range []string{"uri", "happ"} {
		entries[subscriptionCacheKey(token, "format="+format)] = cachedSubscription{
			Body:        []byte("confirmed " + format),
			Headers:     metadata,
			ConfirmedAt: confirmed,
		}
	}
	if err := b.subscriptionCache.replace(entries); err != nil {
		t.Fatal(err)
	}
	request := func(format string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/sub/"+token+"?format="+format, nil)
		r.SetPathValue("token", token)
		r.TLS = &tls.ConnectionState{}
		w := httptest.NewRecorder()
		b.handlePublicSubscription(w, r)
		return w
	}
	w := request("uri")
	for key, value := range metadata {
		if w.Header().Get(key) != value {
			t.Fatalf("proxy lost %s", key)
		}
	}
	broken = true
	for _, format := range []string{"uri", "happ"} {
		w = request(format)
		if w.Code != 200 || w.Body.String() != "confirmed "+format || w.Header().Get("X-Ultra-Quota-Freshness") != "stale" ||
			w.Header().Get("Vary") != "User-Agent" {
			t.Fatal("fallback failed", w.Code, w.Body.String(), w.Header())
		}
		for key, value := range metadata {
			if key != "announce" && w.Header().Get(key) != value {
				t.Fatalf("fallback changed confirmed %s", key)
			}
		}
		msg, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(w.Header().Get("announce"), "base64:"))
		if err != nil || !strings.Contains(string(msg), "устарели") || strings.Contains(string(msg), "Vultr") ||
			!strings.Contains(string(msg), confirmed.Format(time.RFC3339)) {
			t.Fatal("missing stale announcement", string(msg), err)
		}
	}
	// An old snapshot without quota metadata must not inherit the truncated
	// upstream's apparently newer quota.
	entries[subscriptionCacheKey(token, "format=uri")] = cachedSubscription{Body: []byte("confirmed uri"), ConfirmedAt: confirmed}
	if err := b.subscriptionCache.replace(entries); err != nil {
		t.Fatal(err)
	}
	w = request("uri")
	if w.Header().Get("subscription-userinfo") != "" || w.Header().Get("X-Ultra-Quota-Observed-At") != "" {
		t.Fatal("unconfirmed metadata leaked into old cache", w.Header())
	}
	// Staleness never extends the original 24-hour validity window.
	entry := entries[subscriptionCacheKey(token, "format=uri")]
	entry.ConfirmedAt = time.Now().Add(-25 * time.Hour)
	entries[subscriptionCacheKey(token, "format=uri")] = entry
	if err := b.subscriptionCache.replace(entries); err != nil {
		t.Fatal(err)
	}
	if w := request("uri"); w.Code != 503 {
		t.Fatal("expired cache served", w.Code)
	}
}

func TestStaleQuotaDoesNotRenewAtMonthBoundary(t *testing.T) {
	h := http.Header{}
	h.Set("subscription-userinfo", "upload=0; download=1000; total=1000")
	h.Set("X-Ultra-Quota-Period", "2026-10")
	h.Set("X-Ultra-Quota-Resets-At", "2026-11-01T00:00:00Z")
	h.Set("X-Ultra-Quota-State", "exhausted")
	subscriptionmeta.MarkStale(h, time.Date(2026, 10, 31, 23, 59, 0, 0, time.UTC))
	if h.Get("subscription-userinfo") != "upload=0; download=1000; total=1000" || h.Get("X-Ultra-Quota-Period") != "2026-10" ||
		h.Get("X-Ultra-Quota-Resets-At") != "2026-11-01T00:00:00Z" ||
		h.Get("X-Ultra-Quota-State") != "exhausted" {
		t.Fatal("cache renewed quota", h)
	}
}
