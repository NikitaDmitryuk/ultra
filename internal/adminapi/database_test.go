package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/db"
)

func TestDatabaseStatusRequiresAdminAndBoundsObservation(t *testing.T) {
	s, err := NewServer("127.0.0.1:0", "secret", &fakeUserManager{}, nil, nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	primaryHost := "192.0.2.40"
	s.DatabaseStatus = func(ctx context.Context) db.DatabaseStatus {
		calls++
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 5*time.Second {
			t.Error("missing bounded SQL observation deadline")
		}
		return db.DatabaseStatus{PrimaryHost: &primaryHost, ConfiguredHost: "127.0.0.1", ConfiguredPort: 25432, ObservedRole: "standby", Reachable: true}
	}
	for _, token := range []string{"", "wrong", "secret"} {
		r := httptest.NewRequest("GET", "/v1/database", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if token != "secret" {
			if w.Code != http.StatusUnauthorized || calls != 0 {
				t.Fatalf("unauthorized observation: status=%d calls=%d", w.Code, calls)
			}
			continue
		}
		var got db.DatabaseStatus
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" || got.ObservedRole != "standby" || calls != 1 ||
			got.PrimaryHost == nil || *got.PrimaryHost != primaryHost || got.ConfiguredHost != "127.0.0.1" {
			t.Fatalf("unexpected observation: %d %s", w.Code, w.Body)
		}
	}
}

func TestDatabaseStatusUnconfiguredProvider(t *testing.T) {
	s, err := NewServer("127.0.0.1:0", "secret", &fakeUserManager{}, nil, nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/v1/database", nil)
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected unavailable observation: %d %s", w.Code, w.Body)
	}
}
