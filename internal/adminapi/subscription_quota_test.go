package adminapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
)

type quotaSourceFunc func(context.Context, string, time.Time) (db.PoolQuota, error)

func (f quotaSourceFunc) SubscriptionQuota(ctx context.Context, id string, now time.Time) (db.PoolQuota, error) {
	return f(ctx, id, now)
}

func TestSubscriptionQuotaGroupsUseCountriesWithoutProviderNames(t *testing.T) {
	kinds := classifyExitQuotaKinds([]db.ExitBudget{{ID: "nl", Source: "manual"}, {ID: "us", Source: "vultr"}})
	groups := subscriptionQuotaGroupText([]exits.Node{{ID: "nl", CountryCode: "NL"}, {ID: "us", CountryCode: "US"}}, kinds)
	if !strings.Contains(groups, "Общая квота: США") || !strings.Contains(groups, "Отдельная квота: Нидерланды") ||
		strings.Contains(groups, "Vultr") {
		t.Fatal(groups)
	}
}

func TestSubscriptionQuotaOwnerFormatsAndCache(t *testing.T) {
	users := newFakeUserManager()
	user := users.users["u1"]
	user.AccountID = "owner-account"
	users.users["u1"] = user
	s, err := NewServer(
		"127.0.0.1:0",
		"secret",
		users,
		nil,
		&config.Spec{Role: config.RoleBridge, DevMode: true, PublicHost: "localhost", VLESSPort: 443},
		nil,
		nil,
		nil,
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	s.Subscriptions = &cacheSubscriptions{testSubscriptions: testSubscriptions{token: "issued"}}
	observed := time.Date(2026, 10, 12, 13, 0, 0, 0, time.UTC)
	reset := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	source := quotaSourceFunc(func(_ context.Context, id string, now time.Time) (db.PoolQuota, error) {
		if id != "owner-account" || now.IsZero() {
			t.Fatalf("wrong quota owner/time: %s %v", id, now)
		}
		return db.PoolQuota{
			Scope:         "vultr",
			Period:        "2026-10",
			PersonalLimit: 1000,
			Used:          400,
			Remaining:     600,
			ObservedAt:    &observed,
			State:         "ready",
			ResetsAt:      reset,
		}, nil
	})
	request := func(query string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/v1/subscriptions/issued?"+query, nil)
		r.SetPathValue("token", "issued")
		r.Header.Set("User-Agent", "Happ")
		w := httptest.NewRecorder()
		s.handleSubscription(w, r)
		return w
	}
	for _, query := range []string{"format=uri", "format=happ"} {
		s.SubscriptionQuota = nil
		baseline := request(query)
		s.SubscriptionQuota = source
		w := request(query + "&account_id=another-owner")
		if w.Code != 200 || baseline.Body.String() != w.Body.String() || w.Header().Get("Vary") != "User-Agent" {
			t.Fatal("metadata changed subscription representation")
		}
		if got := w.Header().Get("subscription-userinfo"); got != "upload=0; download=400; total=1000" {
			t.Fatal(got)
		}
		if w.Header().Get("X-Ultra-Quota-Observed-At") != observed.Format(time.RFC3339) ||
			w.Header().Get("X-Ultra-Quota-Resets-At") != reset.Format(time.RFC3339) {
			t.Fatal("missing observation/reset")
		}
		if w.Header().Get("X-Ultra-Quota-Scope") != "shared" {
			t.Fatal("provider scope exposed", w.Header().Get("X-Ultra-Quota-Scope"))
		}
		message, e := base64.StdEncoding.DecodeString(strings.TrimPrefix(w.Header().Get("announce"), "base64:"))
		if e != nil || strings.Contains(string(message), "Vultr") || !strings.Contains(string(message), "Общая квота") {
			t.Fatal("missing scoped announcement", string(message), e)
		}
	}
	w := httptest.NewRecorder()
	s.handleSubscriptionCache(w, httptest.NewRequest("GET", "/v1/subscriptions/cache", nil))
	var snapshot struct {
		Entries map[string]subscriptionCacheEntry `json:"entries"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &snapshot) != nil || len(snapshot.Entries) == 0 {
		t.Fatal("cache export failed", w.Body.String())
	}
	for _, entry := range snapshot.Entries {
		if entry.Headers["subscription-userinfo"] != "upload=0; download=400; total=1000" || entry.Headers["announce"] == "" ||
			entry.Headers["X-Ultra-Quota-State"] != "ready" ||
			entry.Headers["X-Ultra-Quota-Scope"] != "shared" {
			t.Fatal("cache dropped quota metadata", entry.Headers)
		}
	}
	for _, test := range []struct {
		name string
		q    db.PoolQuota
		err  error
	}{
		{name: "error", err: errors.New("offline")}, {name: "missing"},
		{name: "unobserved", q: db.PoolQuota{Scope: "vultr", PersonalLimit: 1000, State: "stale"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s.SubscriptionQuota = quotaSourceFunc(
				func(context.Context, string, time.Time) (db.PoolQuota, error) { return test.q, test.err },
			)
			w := request("format=uri")
			if w.Code != 200 || w.Header().Get("subscription-userinfo") != "" ||
				(test.name != "missing" && w.Header().Get("announce") == "") {
				t.Fatal("unknown quota blocked or fabricated", w.Code, w.Header())
			}
			if test.name == "missing" && w.Header().Get("announce") != "" {
				t.Fatal("nonexistent pool announced")
			}
		})
	}
}
