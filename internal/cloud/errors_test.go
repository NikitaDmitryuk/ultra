package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProviderErrorsAreClassifiedWithoutRetainingBody(t *testing.T) {
	for _, tc := range []struct {
		status     int
		body, code string
	}{{401, "Unauthorized IP address", "api_ip_denied"}, {400, "Insufficient funds for this operation", "insufficient_funds"}, {402, "payment review required", "payment_required"}, {403, "IP address not allowed", "api_ip_denied"}, {403, "Not authorized", "api_permission_denied"}, {400, "default_password=secret https://console.example/token", "provider_rejected"}, {429, "slow down", "provider_rate_limit"}} {
		t.Run(tc.code, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": tc.body})
			}))
			defer server.Close()
			api := NewVultr("test")
			api.BaseURL = server.URL
			_, err := api.Create(context.Background(), CreateRequest{})
			var failure APIError
			if !errors.As(err, &failure) || failure.Status != tc.status || failure.Code != tc.code {
				t.Fatalf("classification: %v", err)
			}
			if strings.Contains(err.Error(), tc.body) || strings.Contains(ErrorMessage(tc.code), "secret") {
				t.Fatal("provider body leaked")
			}
		})
	}
}
func TestFailedPurchaseCarriesUsefulMessage(t *testing.T) {
	s, _, _ := testService()
	store := s.Store
	offer, e := s.Quote(context.Background(), 1, "fra", "vc2-1c-1gb", "")
	if e != nil {
		t.Fatal(e)
	}
	op, e := s.Confirm(context.Background(), 1, offer.ID)
	if e != nil {
		t.Fatal(e)
	}
	e = s.fail(context.Background(), op, "creation_rejected", APIError{Status: 400, Code: "insufficient_funds"})
	if e == nil {
		t.Fatal("expected failure")
	}
	saved, e := store.Get(context.Background(), op.ID)
	if e != nil || saved.Error != "insufficient_funds" || saved.HTTPStatus != 400 || !strings.Contains(saved.ErrorMessage, "недостаточно средств") {
		t.Fatal("missing actionable failure", e)
	}
}

func TestStageJournalIncludesFailureAndNoRepeatedUnknownSpam(t *testing.T) {
	s, p, _ := testService()
	p.unknown = true
	ctx := context.Background()
	offer, e := s.Quote(ctx, 1, "fra", "vc2-1c-1gb", "")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Confirm(ctx, 1, offer.ID); e != nil {
		t.Fatal(e)
	}
	if e = s.Step(ctx); !errors.Is(e, ErrUnknownCreation) {
		t.Fatal(e)
	}
	events, _ := s.Store.Events(ctx, offer.ID)
	if len(events) != 2 || events[0].Outcome != "started" || events[1].Outcome != "failed" || events[1].Code != "creation_requires_reconciliation" {
		t.Fatal("missing failure journal", events)
	}
	_ = s.Step(ctx)
	events, _ = s.Store.Events(ctx, offer.ID)
	count := len(events)
	_ = s.Step(ctx)
	events, _ = s.Store.Events(ctx, offer.ID)
	if len(events) != count || p.creates != 1 {
		t.Fatal("unknown retry spam or duplicate purchase")
	}
}
