package cloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBandwidthUsesAccruedAccountCredits(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/account/bandwidth" {
			_, _ = w.Write([]byte(`{"bandwidth":{"current_month_to_date":{"gb_out":300,"instance_bandwidth_credits":100,"free_bandwidth_credits":2000,"purchased_bandwidth_credits":0}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"bandwidth":{"2026-08-31":{"outgoing_bytes":900},"2026-09-01":{"outgoing_bytes":10},"2026-09-02":{"outgoing_bytes":20}}}`))
	}))
	defer s.Close()
	api := NewVultr("fixture")
	api.BaseURL = s.URL
	remaining, e := api.AccountRemaining(context.Background())
	if e != nil || remaining != 1380_000_000_000 {
		t.Fatal(remaining, e)
	}
	used, e := api.InstanceBandwidth(context.Background(), "fixture", time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC))
	if e != nil || used != 30 {
		t.Fatal(used, e)
	}
}
