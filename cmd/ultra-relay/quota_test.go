package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/db"
)

type budgetFixture struct {
	budgets                        []db.ExitBudget
	saved                          []db.BandwidthObservation
	loadErr, watermarkErr, saveErr error
	calls                          *[]string
}

func (b *budgetFixture) Budgets(context.Context) ([]db.ExitBudget, error) {
	return b.budgets, b.loadErr
}
func (b *budgetFixture) ProviderWatermark(context.Context, time.Time) (int64, error) {
	if b.calls != nil {
		*b.calls = append(*b.calls, "watermark")
	}
	return 123, b.watermarkErr
}
func (b *budgetFixture) SaveBandwidth(_ context.Context, v []db.BandwidthObservation, _ time.Time) error {
	b.saved = v
	return b.saveErr
}

type bandwidthFixture struct {
	err   error
	calls *[]string
}

func (b *bandwidthFixture) AccountBandwidth(context.Context) (cloud.AccountBandwidth, error) {
	if b.calls != nil {
		*b.calls = append(*b.calls, "request")
	}
	return cloud.AccountBandwidth{Accrued: 5000, Used: 999, Remaining: 3001}, b.err
}

func TestBandwidthUsesOneAccruedPoolWithoutExitShares(t *testing.T) {
	calls := []string{}
	repo := &budgetFixture{
		calls: &calls,
		budgets: []db.ExitBudget{
			{ID: "a", Instance: "a", Source: "vultr", Enabled: true, Monthly: 100},
			{ID: "b", Instance: "b", Source: "vultr", Enabled: true, Monthly: 9000},
			{ID: "off", Source: "vultr"},
			{ID: "manual", Source: "manual", Enabled: true},
		},
	}
	err := refreshBandwidth(context.Background(), repo, &bandwidthFixture{calls: &calls}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0] != "watermark" || calls[1] != "request" {
		t.Fatal("observation watermark order", calls)
	}
	if len(repo.saved) != 2 {
		t.Fatal(repo.saved)
	}
	for _, o := range repo.saved {
		if !o.Pool || o.Accrued != 5000 || o.AccountUsed != 999 || o.Remaining != 3001 || o.LocalWatermark != 123 {
			t.Fatal("split pool", o)
		}
	}
}
func TestBandwidthStorageAndProviderFailures(t *testing.T) {
	for _, stage := range []string{"budgets", "membership", "save_bandwidth", "account_bandwidth"} {
		t.Run(stage, func(t *testing.T) {
			repo := &budgetFixture{budgets: []db.ExitBudget{{ID: "a", Source: "vultr", Enabled: true}}}
			api := &bandwidthFixture{}
			switch stage {
			case "budgets":
				repo.loadErr = context.DeadlineExceeded
			case "membership":
				repo.watermarkErr = context.DeadlineExceeded
			case "save_bandwidth":
				repo.saveErr = context.DeadlineExceeded
			case "account_bandwidth":
				api.err = context.DeadlineExceeded
			}
			err := refreshBandwidth(context.Background(), repo, api, time.Now())
			var failure bandwidthRefreshError
			if !errors.As(err, &failure) || failure.stage != stage || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal(err)
			}
			if stage == "account_bandwidth" && (len(repo.saved) != 1 || repo.saved[0].Error == "") {
				t.Fatal("outage not saved")
			}
		})
	}
}
func TestBandwidthMissingAPIUsesConfirmedOutage(t *testing.T) {
	r := &budgetFixture{budgets: []db.ExitBudget{{ID: "a", Source: "vultr", Enabled: true}}}
	if err := refreshBandwidth(context.Background(), r, nil, time.Now()); err == nil || len(r.saved) != 1 || r.saved[0].Error == "" {
		t.Fatal(err, r.saved)
	}
}
