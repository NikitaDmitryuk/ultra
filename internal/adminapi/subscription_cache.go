package adminapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/subscriptionmeta"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"
)

type subscriptionCacheEntry struct {
	Body        []byte            `json:"body"`
	Headers     map[string]string `json:"headers"`
	ConfirmedAt time.Time         `json:"confirmed_at"`
}

// Complete read-only export, never including raw subscription tokens in its response.
func (s *Server) handleSubscriptionCache(w http.ResponseWriter, r *http.Request) {
	source, ok := s.Subscriptions.(interface {
		ListActiveTokens(context.Context) ([]string, error)
	})
	if !ok {
		http.Error(w, "subscription cache unavailable", http.StatusServiceUnavailable)
		return
	}
	tokens, err := source.ListActiveTokens(r.Context())
	if err != nil {
		http.Error(w, "subscription cache unavailable", http.StatusServiceUnavailable)
		return
	}
	entries := map[string]subscriptionCacheEntry{}
	now := time.Now().UTC()
	for _, token := range tokens {
		digest := sha256.Sum256([]byte(token))
		prefix := hex.EncodeToString(digest[:]) + "?"
		resolveReq := httptest.NewRequest("GET", "/", nil).WithContext(r.Context())
		resolveReq.SetPathValue("token", token)
		id, user, ok := s.resolveSubscriptionUser(httptest.NewRecorder(), resolveReq)
		if !ok {
			http.Error(w, "subscription cache incomplete", http.StatusServiceUnavailable)
			return
		}
		_, _, _, nodes := s.clientExitSelection(user)
		quotaHeaders := http.Header{}
		s.setSubscriptionQuota(r.Context(), quotaHeaders, user.AccountID, nodes)
		seen := map[string]bool{}
		for _, query := range []string{"", "format=uri", "format=happ", "format=uri&transport=xhttp-tls"} {
			req := httptest.NewRequest("GET", "/v1/subscriptions/"+url.PathEscape(token)+"?"+query, nil).WithContext(r.Context())
			req.SetPathValue("token", token)
			req.Header.Set("User-Agent", "Happ")
			format, err := config.ResolveSubscriptionFormat(req.URL.Query().Get("format"), req.URL.Query().Get("transport"), req.UserAgent(), s.spec.HappDefaultJSON)
			if err != nil {
				continue
			}
			key := prefix + config.SubscriptionCacheQuery(format, req.URL.Query().Get("transport"))
			if seen[key] {
				continue
			}
			seen[key] = true
			recorder := httptest.NewRecorder()
			s.renderSubscription(recorder, req, id, user, quotaHeaders)
			if recorder.Code == http.StatusBadRequest && query == "format=happ" {
				continue
			}
			if recorder.Code == http.StatusServiceUnavailable && query == "format=uri&transport=xhttp-tls" {
				continue
			}
			if recorder.Code != 200 {
				http.Error(w, "subscription cache incomplete", http.StatusServiceUnavailable)
				return
			}
			headers := map[string]string{}
			for _, key := range subscriptionmeta.Headers {
				if value := recorder.Header().Get(key); value != "" {
					headers[key] = value
				}
			}
			entries[key] = subscriptionCacheEntry{Body: recorder.Body.Bytes(), Headers: headers, ConfirmedAt: now}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(struct {
		Version         int                               `json:"version"`
		HappDefaultJSON bool                              `json:"happ_default_json,omitempty"`
		Entries         map[string]subscriptionCacheEntry `json:"entries"`
	}{1, s.spec.HappDefaultJSON, entries})
}
