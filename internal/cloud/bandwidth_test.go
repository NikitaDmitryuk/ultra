package cloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBandwidthUsesPaidInstanceCountAndProviderUsage(t *testing.T) {
	calls := map[string]int{}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls[r.URL.Path]++
		if calls[r.URL.Path] == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		if r.URL.Path == "/account/bandwidth" {
			_, _ = w.Write(
				[]byte(
					`{"bandwidth":{"current_month_to_date":{"gb_out":300}}}`,
				),
			)
			return
		}
		if r.URL.Query().Get("cursor") == "next" {
			_, _ = w.Write([]byte(`{"instances":[{"id":"running"}],"meta":{"links":{"next":""}}}`))
		} else {
			_, _ = w.Write([]byte(`{"instances":[{"id":"stopped","power_status":"stopped"}],"meta":{"links":{"next":"next"}}}`))
		}
	}))
	defer s.Close()
	api := NewVultr("fixture")
	api.BaseURL = s.URL
	remaining, e := api.AccountRemaining(context.Background())
	if e != nil || remaining != 2_900_000_000_000 {
		t.Fatal(remaining, e)
	}
	if calls["/account/bandwidth"] != 2 || calls["/instances"] != 3 {
		t.Fatal("transient GET failures were not retried", calls)
	}
}

func TestBandwidthCapacityBaseStoppedAndDeleted(t *testing.T) {
	for _, test := range []struct {
		name      string
		instances string
		want      int64
	}{
		{name: "no instances after deletion", instances: `[]`, want: 2_000_000_000_000},
		{name: "stopped instance remains billable", instances: `[{"id":"stopped","power_status":"stopped"}]`, want: 3_000_000_000_000},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/account/bandwidth" {
					_, _ = w.Write([]byte(`{"bandwidth":{"current_month_to_date":{"gb_out":0}}}`))
					return
				}
				_, _ = w.Write([]byte(`{"instances":` + test.instances + `,"meta":{"links":{"next":""}}}`))
			}))
			defer server.Close()
			api := NewVultr("fixture")
			api.BaseURL = server.URL
			got, err := api.AccountBandwidth(context.Background())
			if err != nil || got.Accrued != test.want || got.Used != 0 {
				t.Fatalf("capacity=%d used=%d err=%v", got.Accrued, got.Used, err)
			}
		})
	}
}

func TestAccountPoolRequiresConfirmedUsage(t *testing.T) {
	for _, body := range []string{
		`{"bandwidth":{}}`,
		`{"bandwidth":{"current_month_to_date":{}}}`,
		`{"bandwidth":{"current_month_to_date":{"gb_out":null}}}`,
		`{"bandwidth":{"current_month_to_date":{"gb_out":-1}}}`,
		`{"bandwidth":{"current_month_to_date":{"gb_out":1e30}}}`,
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
