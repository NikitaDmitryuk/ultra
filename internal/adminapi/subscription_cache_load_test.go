package adminapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/NikitaDmitryuk/ultra/internal/subscriptionmeta"
)

type countingCacheSubscriptions struct {
	testSubscriptions
	resolves   int
	resolveErr error
}

func (s *countingCacheSubscriptions) ListActiveTokens(context.Context) ([]string, error) {
	return []string{s.token}, nil
}
func (s *countingCacheSubscriptions) Resolve(ctx context.Context, token string) (string, error) {
	s.resolves++
	if s.resolveErr != nil {
		return "", s.resolveErr
	}
	return s.testSubscriptions.Resolve(ctx, token)
}

func TestSubscriptionCacheReadsSourceOncePerToken(t *testing.T) {
	for _, happDefault := range []bool{false, true} {
		for _, quotaUnavailable := range []bool{false, true} {
			t.Run(fmtCacheCase(happDefault, quotaUnavailable), func(t *testing.T) {
				users := newFakeUserManager()
				user := users.users["u1"]
				user.AccountID = "owner-account"
				users.users["u1"] = user
				spec := &config.Spec{
					Role:            config.RoleBridge,
					PublicHost:      "localhost",
					VLESSPort:       443,
					HappDefaultJSON: happDefault,
					Reality:         config.RealitySpec{ServerNames: []string{"vpn.example"}},
					PublicXHTTPTLS:  &config.PublicXHTTPTLSSpec{Port: 5443, ServerName: "vpn.example", Path: "/connect"},
				}
				server, err := NewServer("127.0.0.1:0", "admin", users, nil, spec, nil, nil, nil, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				source := &countingCacheSubscriptions{testSubscriptions: testSubscriptions{token: "issued"}}
				server.Subscriptions = source
				quotaCalls := 0
				observed := time.Now().UTC()
				server.SubscriptionQuota = quotaSourceFunc(func(context.Context, string, time.Time) (db.PoolQuota, error) {
					quotaCalls++
					if quotaUnavailable {
						return db.PoolQuota{}, errors.New("offline")
					}
					return db.PoolQuota{Scope: "vultr", State: "ready", PersonalLimit: 1000, Used: 400, ObservedAt: &observed}, nil
				})
				w := httptest.NewRecorder()
				server.handleSubscriptionCache(w, httptest.NewRequest("GET", "/v1/subscriptions/cache", nil))
				if w.Code != http.StatusOK {
					t.Fatal(w.Code)
				}
				if source.resolves != 1 || quotaCalls != 1 {
					t.Fatalf("source calls: resolve=%d quota=%d, want 1 each", source.resolves, quotaCalls)
				}
				var snapshot struct {
					Entries map[string]subscriptionCacheEntry `json:"entries"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &snapshot); err != nil {
					t.Fatal(err)
				}
				if len(snapshot.Entries) != 3 {
					t.Fatalf("entries=%d, want 3 unique variants", len(snapshot.Entries))
				}
				for _, query := range []string{"format=uri", "format=happ", "format=uri&transport=xhttp-tls"} {
					r := httptest.NewRequest("GET", "/?"+query, nil)
					r.SetPathValue("token", "issued")
					r.Header.Set("User-Agent", "Happ")
					direct := httptest.NewRecorder()
					server.handleSubscription(direct, r)
					if direct.Code != http.StatusOK {
						t.Fatal(direct.Code)
					}
					format, err := config.ResolveSubscriptionFormat(
						r.URL.Query().Get("format"),
						r.URL.Query().Get("transport"),
						r.UserAgent(),
						happDefault,
					)
					if err != nil {
						t.Fatal(err)
					}
					key := fmt.Sprintf(
						"%x?%s",
						sha256.Sum256([]byte("issued")),
						config.SubscriptionCacheQuery(format, r.URL.Query().Get("transport")),
					)
					entry, ok := snapshot.Entries[key]
					if !ok {
						t.Fatalf("missing cached variant %s", query)
					}
					if !bytes.Equal(entry.Body, direct.Body.Bytes()) {
						t.Fatalf("body differs for %s", query)
					}
					for _, header := range subscriptionmeta.Headers {
						if entry.Headers[header] != direct.Header().Get(header) {
							t.Fatalf("header %s differs for %s", header, query)
						}
					}
				}

				// A later export must confirm the source and quota again.
				source.resolves, quotaCalls = 0, 0
				server.handleSubscriptionCache(httptest.NewRecorder(), httptest.NewRequest("GET", "/v1/subscriptions/cache", nil))
				if source.resolves != 1 || quotaCalls != 1 {
					t.Fatalf("later export source calls: resolve=%d quota=%d", source.resolves, quotaCalls)
				}
				source.resolveErr = errors.New("unconfirmed source")
				w = httptest.NewRecorder()
				server.handleSubscriptionCache(w, httptest.NewRequest("GET", "/v1/subscriptions/cache", nil))
				if w.Code != http.StatusServiceUnavailable {
					t.Fatal("unconfirmed token accepted", w.Code)
				}
			})
		}
	}
}

func fmtCacheCase(happDefault, unavailable bool) string {
	name := "uri-default"
	if happDefault {
		name = "happ-default"
	}
	if unavailable {
		name += "/unknown-quota"
	} else {
		name += "/confirmed-quota"
	}
	return name
}
