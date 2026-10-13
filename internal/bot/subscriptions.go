package bot

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/NikitaDmitryuk/ultra/internal/subscriptionmeta"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

func validBotUsername(username string) bool {
	if len(username) < 5 || len(username) > 32 {
		return false
	}
	for _, r := range username {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

func (b *Bot) subscriptionSupportURL() string {
	username := b.telegramSelf().UserName
	if !validBotUsername(username) && b.subscriptionCache != nil {
		b.subscriptionCache.mu.RLock()
		username = b.subscriptionCache.botUsername
		b.subscriptionCache.mu.RUnlock()
	}
	if !validBotUsername(username) {
		return ""
	}
	return (&url.URL{Scheme: "https", Host: "t.me", Path: "/" + username, RawQuery: "start=member"}).String()
}

func (b *Bot) setSubscriptionSupportURL(h http.Header) {
	if target := b.subscriptionSupportURL(); target != "" {
		h.Set("support-url", target)
	} else {
		h.Del("support-url")
	}
}

func (b *Bot) handlePublicSubscription(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	defer func() {
		if elapsed := time.Since(started); elapsed >= time.Second {
			b.log.Warn("slow subscription response", "duration_ms", elapsed.Milliseconds())
		}
	}()

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "User-Agent")
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	fromLoopback := net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
	if r.TLS == nil && (!fromLoopback || r.Header.Get("X-Forwarded-Proto") != "https") {
		http.Error(w, "HTTPS required", http.StatusUpgradeRequired)
		return
	}
	token := r.PathValue("token")
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		http.NotFound(w, r)
		return
	}
	var acceptance *happAcceptance
	if r.URL.Query().Get("preview") == "reserve-live" {
		if r.URL.Query().Get("format") != "happ" || r.URL.Query().Get("transport") != "" {
			http.Error(w, "explicit Happ format required", http.StatusBadRequest)
			return
		}
		acceptance, err = loadHappAcceptance(b.happAcceptanceFile, token, time.Now())
		if err != nil {
			http.NotFound(w, r)
			return
		}
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, b.adminAPIURL+"/v1/subscriptions/"+url.PathEscape(token), nil)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	req.URL.RawQuery = url.Values{"format": r.URL.Query()["format"], "transport": r.URL.Query()["transport"], "preview": r.URL.Query()["preview"]}.Encode()
	if acceptance != nil {
		query := req.URL.Query()
		query.Set("preview", "reserve")
		req.URL.RawQuery = query.Encode()
	}
	cacheKey, formatErr := b.subscriptionFallbackKey(token, r)
	if formatErr != nil {
		http.Error(w, formatErr.Error(), http.StatusBadRequest)
		return
	}
	req.Header.Set("User-Agent", r.UserAgent())
	req.Header.Set("Authorization", "Bearer "+b.adminAPIToken)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		if b.serveSubscriptionFallback(w, cacheKey, token, r) {
			return
		}
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= 500 && b.serveSubscriptionFallback(w, cacheKey, token, r) {
			return
		}
		if resp.StatusCode == 404 && b.subscriptionCache != nil {
			b.subscriptionCache.invalidate(subscriptionDigest(token))
		}
		http.Error(w, "subscription unavailable", resp.StatusCode)
		return
	}
	w.Header().Set("Server-Timing", fmt.Sprintf("relay;dur=%.1f", float64(time.Since(started).Microseconds())/1000))
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if readErr != nil || len(body) > 1<<20 {
		if b.serveSubscriptionFallback(w, cacheKey, token, r) {
			return
		}
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	for _, key := range subscriptionmeta.Headers {
		if value := resp.Header.Get(key); value != "" {
			w.Header().Set(key, value)
		}
	}
	b.setSubscriptionSupportURL(w.Header())
	if acceptance != nil {
		// Cleanup or expiry during the upstream request revokes the preview too.
		acceptance, err = loadHappAcceptance(b.happAcceptanceFile, token, time.Now())
		if err != nil {
			http.Error(w, "acceptance profile unavailable", http.StatusServiceUnavailable)
			return
		}
		body, err = acceptance.rewrite(body)
		if err != nil {
			http.Error(w, "acceptance profile unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	if b.happAcceptanceFile != "" {
		if _, err := loadHappAcceptance(b.happAcceptanceFile, token, time.Now()); err == nil {
			b.captureHappAcceptanceUserAgent(r.UserAgent())
		}
	}
	_, _ = w.Write(body)
}
func (b *Bot) handleRotateSubscription(w http.ResponseWriter, r *http.Request) {
	if _, ok := b.mustAdmin(w, r); !ok {
		return
	}
	base, err := url.Parse(b.miniAppURL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		http.Error(w, "HTTPS Mini App URL required", http.StatusServiceUnavailable)
		return
	}
	data, err := b.adminPost(r.Context(), "/v1/users/"+url.PathEscape(r.PathValue("uuid"))+"/subscription", nil)
	if err != nil {
		http.Error(w, "cannot issue subscription", http.StatusBadGateway)
		return
	}
	var reply struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(data, &reply) != nil || reply.Token == "" {
		http.Error(w, "bad response", http.StatusBadGateway)
		return
	}
	base.Path = "/sub/" + reply.Token
	base.RawPath = ""
	base.RawQuery = ""
	base.Fragment = ""
	w.Header().Set("Cache-Control", "no-store")
	jsonOK(w, map[string]string{"url": base.String(), "happ_url": "happ://add/" + base.String()})
}
func (b *Bot) handleRevokeSubscription(w http.ResponseWriter, r *http.Request) {
	if _, ok := b.mustAdmin(w, r); !ok {
		return
	}
	err := b.adminDelete(r.Context(), "/v1/users/"+url.PathEscape(r.PathValue("uuid"))+"/subscription")
	if err != nil {
		http.Error(w, "cannot revoke subscription", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
