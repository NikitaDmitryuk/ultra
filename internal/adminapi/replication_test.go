package adminapi

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBridgeReplicationUnavailableObservation(t *testing.T) {
	s, err := NewServer("127.0.0.1:0", "secret", &fakeUserManager{}, nil, nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, configured := range []bool{false, true} {
		if configured {
			s.ReplicationStatus = func(ctx context.Context) (any, error) {
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 5*time.Second {
					t.Error("live observation must have a bounded query deadline")
				}
				return nil, errors.New("private database connection detail")
			}
		}
		r := httptest.NewRequest("GET", "/v1/cloud/replicas", nil)
		r.Header.Set("Authorization", "Bearer secret")
		w := httptest.NewRecorder()
		s.authMiddleware(s.mux).ServeHTTP(w, r)
		if w.Code != 503 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("expected uncached unavailable observation: %d %v", w.Code, w.Header())
		}
		if strings.Contains(w.Body.String(), "private database") || strings.Contains(w.Body.String(), "not_configured") {
			t.Fatalf("unavailable observation leaked details or claimed configuration state: %s", w.Body)
		}
	}
}
