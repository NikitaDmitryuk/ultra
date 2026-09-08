package main

import (
	"context"
	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/db"
	"testing"
	"time"
)

type budgetFixture struct {
	budgets []db.ExitBudget
	updates map[string]int64
	shares  map[string]int64
	codes   map[string]string
}

func (b *budgetFixture) Budgets(context.Context) ([]db.ExitBudget, error) { return b.budgets, nil }
func (b *budgetFixture) SaveBandwidth(_ context.Context, updates []db.BandwidthObservation, _ time.Time) error {
	for _, o := range updates {
		if o.Error == "" {
			b.updates[o.ID] = o.Monthly
		}
		b.shares[o.ID] = o.Remaining
		b.codes[o.ID] = o.Error
	}
	return nil
}

type bandwidthFixture struct{ plan string }

func (b bandwidthFixture) Plans(context.Context) ([]cloud.Plan, error) {
	return []cloud.Plan{{ID: "plan", Bandwidth: 1024}}, nil
}
func (b bandwidthFixture) Get(context.Context, string) (cloud.Instance, error) {
	return cloud.Instance{Plan: b.plan, AllowedBandwidth: 1}, nil
}
func (b bandwidthFixture) AccountRemaining(context.Context) (int64, error) { return 1001, nil }
func (b bandwidthFixture) InstanceBandwidth(context.Context, string, time.Time) (int64, error) {
	return 0, nil
}
func TestBandwidthUsesActualCatalogPlanAndOneAccountPool(t *testing.T) {
	for _, plan := range []string{"plan", "unknown"} {
		t.Run(plan, func(t *testing.T) {
			r := &budgetFixture{budgets: []db.ExitBudget{{ID: "a", Instance: "a", Source: "vultr", Enabled: true, Monthly: 1_000_000_000}, {ID: "b", Instance: "b", Source: "vultr", Enabled: true, Monthly: 1024_000_000_000}, {ID: "off", Source: "vultr", Monthly: 500, Enabled: false}}, updates: map[string]int64{}, shares: map[string]int64{}, codes: map[string]string{}}
			err := refreshBandwidth(context.Background(), r, bandwidthFixture{plan}, time.Now())
			if plan == "unknown" {
				if err == nil || len(r.updates) != 0 || r.codes["a"] == "" {
					t.Fatal("unknown tariff accepted", r)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"a", "b"} {
				if r.updates[id] != 1024_000_000_000 || r.shares[id] != 500 {
					t.Fatalf("incorrect budget/share: %+v", r)
				}
			}
			if _, ok := r.shares["off"]; ok {
				t.Fatal("disabled node reserved quota")
			}
		})
	}
}
