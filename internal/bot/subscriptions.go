package bot

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

func (b *Bot) handlePublicSubscription(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
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
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, b.adminAPIURL+"/v1/subscriptions/"+url.PathEscape(token), nil)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	req.Header.Set("Authorization", "Bearer "+b.adminAPIToken)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		http.Error(w, "subscription unavailable", resp.StatusCode)
		return
	}
	for _, key := range []string{"Content-Type", "profile-title", "profile-update-interval"} {
		w.Header().Set(key, resp.Header.Get(key))
	}
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 1<<20))
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
