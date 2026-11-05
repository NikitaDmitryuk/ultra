package bot

import (
	"encoding/base64"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestSubscriptionSupportURLSurvivesRestartAndCachedFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subscriptions.json")
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	key := subscriptionCacheKey(token, "format=uri")
	b := &Bot{}
	if err := b.ConfigureSubscriptionCache(path); err != nil {
		t.Fatal(err)
	}
	if err := b.subscriptionCache.replace(map[string]cachedSubscription{key: {Body: []byte("vless://cached\n"), ConfirmedAt: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	b.subscriptionCache.mu.Lock()
	b.subscriptionCache.happExitPing = true
	b.subscriptionCache.entries[key] = cachedSubscription{Body: []byte("vless://cached\n"), Headers: map[string]string{
		"providerid": "provider-123", "ping-type": "proxy-head", "check-url-via-proxy": "http://192.0.2.254/generate_204",
	}, ConfirmedAt: time.Now()}
	if err := b.subscriptionCache.replaceLocked(b.subscriptionCache.entries); err != nil {
		b.subscriptionCache.mu.Unlock()
		t.Fatal(err)
	}
	b.subscriptionCache.mu.Unlock()
	if err := b.subscriptionCache.setBotUsername("first_test_bot"); err != nil {
		t.Fatal(err)
	}
	restarted := &Bot{}
	if err := restarted.ConfigureSubscriptionCache(path); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/sub/"+token+"?format=uri", nil)
	req.SetPathValue("token", token)
	w := httptest.NewRecorder()
	if !restarted.serveSubscriptionFallback(w, key, token, req) {
		t.Fatal("confirmed fallback unavailable")
	}
	if w.Header().Get("providerid") != "provider-123" || w.Header().Get("ping-type") != "proxy-head" ||
		w.Header().Get("check-url-via-proxy") != "http://192.0.2.254/generate_204" || !restarted.subscriptionCache.happExitPing {
		t.Fatal("exit ping metadata did not survive restart and stale fallback", w.Header())
	}
	if got := w.Header().Get("support-url"); got != "https://t.me/first_test_bot?start=member" {
		t.Fatal(got)
	}
	if err := restarted.subscriptionCache.setBotUsername("renamed_test_bot"); err != nil {
		t.Fatal(err)
	}
	again := &Bot{}
	if err := again.ConfigureSubscriptionCache(path); err != nil {
		t.Fatal(err)
	}
	if got := again.subscriptionSupportURL(); got != "https://t.me/renamed_test_bot?start=member" {
		t.Fatal(got)
	}
}

func TestSubscriptionSupportURLRejectsInvalidUsernameWithoutBreakingCache(t *testing.T) {
	b := &Bot{}
	if err := b.ConfigureSubscriptionCache(filepath.Join(t.TempDir(), "subscriptions.json")); err != nil {
		t.Fatal(err)
	}
	if err := b.subscriptionCache.setBotUsername("bad/name"); err == nil {
		t.Fatal("invalid username accepted")
	}
	if got := b.subscriptionSupportURL(); got != "" {
		t.Fatal(got)
	}
}

func TestSubscriptionMetadataCacheRequiresSingleGeneration(t *testing.T) {
	entry := cachedSubscription{Headers: map[string]string{
		"providerid": "provider-123", "ping-type": "proxy-head", "check-url-via-proxy": "http://192.0.2.254/generate_204",
	}}
	if validSubscriptionMetadataGeneration(subscriptionCacheSnapshot{Entries: map[string]cachedSubscription{"one": entry}}) {
		t.Fatal("disabled snapshot accepted enabled metadata")
	}
	if !validSubscriptionMetadataGeneration(
		subscriptionCacheSnapshot{HappExitPing: true, Entries: map[string]cachedSubscription{"one": entry}},
	) {
		t.Fatal("consistent enabled snapshot rejected")
	}
	other := entry
	other.Headers = map[string]string{
		"providerid": "provider-456", "ping-type": "proxy-head", "check-url-via-proxy": "http://192.0.2.254/generate_204",
	}
	if validSubscriptionMetadataGeneration(
		subscriptionCacheSnapshot{HappExitPing: true, Entries: map[string]cachedSubscription{"one": entry, "two": other}},
	) {
		t.Fatal("mixed provider IDs accepted in one cache generation")
	}
}
