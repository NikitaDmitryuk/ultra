package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBandwidthUsesCurrentAccruedCreditsAndProviderUsage(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/account/bandwidth" {
			t.Errorf("unexpected inventory dependency: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write(
			[]byte(
				`{"bandwidth":{"current_month_to_date":{"gb_out":300,"instance_bandwidth_credits":123,"free_bandwidth_credits":2048,"purchased_bandwidth_credits":50},"current_month_projected":{"gb_out":500,"instance_bandwidth_credits":4000,"free_bandwidth_credits":2048,"purchased_bandwidth_credits":50}}}`,
			),
		)
	}))
	defer server.Close()
	api := NewVultr("fixture")
	api.BaseURL = server.URL
	got, err := api.AccountBandwidth(context.Background())
	const capacity int64 = 2221 * 1_000_000_000
	if err != nil || got.Accrued != capacity || got.Used != 300_000_000_000 || got.Remaining != capacity*4/5-300_000_000_000 {
		t.Fatalf("observation=%+v err=%v", got, err)
	}
	if calls != 2 {
		t.Fatalf("transient GET failure not retried: %d calls", calls)
	}
}

func TestBandwidthZeroAndExhaustedPool(t *testing.T) {
	for _, test := range []struct {
		name, current string
		want          AccountBandwidth
	}{
		{"zero confirmed credits", `{"gb_out":0,"instance_bandwidth_credits":0,"free_bandwidth_credits":0,"purchased_bandwidth_credits":0}`, AccountBandwidth{}},
		{"free pool remains without inventory", `{"gb_out":0,"instance_bandwidth_credits":0,"free_bandwidth_credits":2048,"purchased_bandwidth_credits":0}`, AccountBandwidth{Accrued: 2048_000_000_000, Remaining: 1638_400_000_000}},
		{"exhausted pool", `{"gb_out":2000,"instance_bandwidth_credits":0,"free_bandwidth_credits":2048,"purchased_bandwidth_credits":0}`, AccountBandwidth{Accrued: 2048_000_000_000, Used: 2000_000_000_000}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprintf(w, `{"bandwidth":{"current_month_to_date":%s}}`, test.current)
			}))
			defer server.Close()
			api := NewVultr("fixture")
			api.BaseURL = server.URL
			got, err := api.AccountBandwidth(context.Background())
			if err != nil || got != test.want {
				t.Fatalf("got=%+v want=%+v err=%v", got, test.want, err)
			}
		})
	}
}

func TestAccountPoolRequiresConfirmedCredits(t *testing.T) {
	for _, field := range []string{"instance_bandwidth_credits", "free_bandwidth_credits", "purchased_bandwidth_credits"} {
		for _, invalid := range []any{"missing", nil, -1, 0.5, "unknown", int64(math.MaxInt64), int64(math.MaxInt64 / 1_000_000_000)} {
			t.Run(fmt.Sprintf("%s/%v", field, invalid), func(t *testing.T) {
				current := map[string]any{
					"gb_out":                      0,
					"instance_bandwidth_credits":  1,
					"free_bandwidth_credits":      2048,
					"purchased_bandwidth_credits": 0,
				}
				if invalid == "missing" {
					delete(current, field)
				} else {
					current[field] = invalid
				}
				body, err := json.Marshal(map[string]any{"bandwidth": map[string]any{"current_month_to_date": current}})
				if err != nil {
					t.Fatal(err)
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
				defer server.Close()
				api := NewVultr("fixture")
				api.BaseURL = server.URL
				if _, err := api.AccountBandwidth(context.Background()); err == nil {
					t.Fatal("unconfirmed credits granted budget")
				}
			})
		}
	}
}

func TestAccountPoolRequiresConfirmedUsage(t *testing.T) {
	for _, body := range []string{
		`{"bandwidth":{}}`,
		`{"bandwidth":{"current_month_to_date":{}}}`,
		`{"bandwidth":{"current_month_to_date":{"gb_out":null,"instance_bandwidth_credits":0,"free_bandwidth_credits":2048,"purchased_bandwidth_credits":0}}}`,
		`{"bandwidth":{"current_month_to_date":{"gb_out":-1,"instance_bandwidth_credits":0,"free_bandwidth_credits":2048,"purchased_bandwidth_credits":0}}}`,
		`{"bandwidth":{"current_month_to_date":{"gb_out":1e30,"instance_bandwidth_credits":0,"free_bandwidth_credits":2048,"purchased_bandwidth_credits":0}}}`,
	} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			api := NewVultr("fixture")
			api.BaseURL = server.URL
			if _, err := api.AccountBandwidth(context.Background()); err == nil {
				t.Fatal("incomplete observation granted budget")
			}
		})
	}
}
