package main

import (
	"context"
	"errors"
	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/db"
	"math"
	"testing"
	"time"
)

type budgetFixture struct {
	budgets          []db.ExitBudget
	updates          map[string]int64
	shares           map[string]int64
	codes            map[string]string
	loadErr, saveErr error
}

func (b *budgetFixture) Budgets(context.Context) ([]db.ExitBudget, error) {
	return b.budgets, b.loadErr
}
func (b *budgetFixture) SaveBandwidth(_ context.Context, updates []db.BandwidthObservation, _ time.Time) error {
	if b.saveErr != nil {
		return b.saveErr
	}
	for _, o := range updates {
		if o.Error == "" {
			b.updates[o.ID] = o.Monthly
		}
		b.shares[o.ID] = o.Remaining
		b.codes[o.ID] = o.Error
	}
	return nil
}

func TestBandwidthStorageFailureStage(t *testing.T) {
	for _, stage := range []string{"budgets", "save_bandwidth"} {
		t.Run(stage, func(t *testing.T) {
			r := &budgetFixture{budgets: []db.ExitBudget{{Source: "vultr", Enabled: true, PlanID: "plan", PlanBandwidth: 1024}}}
			if stage == "budgets" {
				r.loadErr = context.DeadlineExceeded
			} else {
				r.saveErr = context.DeadlineExceeded
			}
			err := refreshBandwidth(context.Background(), r, &bandwidthFixture{plan: "plan"}, time.Now())
			var failure bandwidthRefreshError
			if !errors.As(err, &failure) || failure.stage != stage || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("failure stage lost: %v", err)
			}
		})
	}
}

type bandwidthFixture struct {
	plan                                            string
	plansErr, accountErr, instanceErr, bandwidthErr error
	plansCalls                                      int
}

func (b *bandwidthFixture) Plans(context.Context) ([]cloud.Plan, error) {
	b.plansCalls++
	return []cloud.Plan{{ID: "plan", Bandwidth: 1024}}, b.plansErr
}
func (b *bandwidthFixture) Get(context.Context, string) (cloud.Instance, error) {
	return cloud.Instance{Plan: b.plan, AllowedBandwidth: 1}, b.instanceErr
}
func (b *bandwidthFixture) AccountRemaining(context.Context) (int64, error) {
	return 1001, b.accountErr
}
func (b *bandwidthFixture) InstanceBandwidth(context.Context, string, time.Time) (int64, error) {
	return 0, b.bandwidthErr
}
func TestBandwidthUsesActualCatalogPlanAndOneAccountPool(t *testing.T) {
	for _, plan := range []string{"plan", "unknown"} {
		t.Run(plan, func(t *testing.T) {
			r := &budgetFixture{budgets: []db.ExitBudget{{ID: "a", Instance: "a", Source: "vultr", Enabled: true, Monthly: 1_000_000_000}, {ID: "b", Instance: "b", Source: "vultr", Enabled: true, Monthly: 1024_000_000_000}, {ID: "off", Source: "vultr", Monthly: 500, Enabled: false}}, updates: map[string]int64{}, shares: map[string]int64{}, codes: map[string]string{}}
			err := refreshBandwidth(context.Background(), r, &bandwidthFixture{plan: plan}, time.Now())
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

func TestBandwidthSavedPlanAndProviderFailures(t *testing.T) {
	providerErr := cloud.APIError{Status: 503, Code: "provider_unavailable"}
	for _, tt := range []struct {
		name, savedPlan, stage string
		bandwidth              int64
		api                    bandwidthFixture
		wantCalls              int
	}{
		{name: "saved", savedPlan: "plan", bandwidth: 1024, api: bandwidthFixture{plan: "plan", plansErr: providerErr}},
		{name: "missing", api: bandwidthFixture{plan: "plan"}, wantCalls: 1},
		{name: "changed", savedPlan: "old", bandwidth: 1024, api: bandwidthFixture{plan: "plan"}, wantCalls: 1},
		{name: "invalid", savedPlan: "plan", bandwidth: -1, api: bandwidthFixture{plan: "plan"}, wantCalls: 1},
		{name: "overflow", savedPlan: "plan", bandwidth: math.MaxInt64, api: bandwidthFixture{plan: "plan"}, wantCalls: 1},
		{name: "catalog failed", api: bandwidthFixture{plan: "plan", plansErr: providerErr}, wantCalls: 1, stage: "plan"},
		{name: "unknown", api: bandwidthFixture{plan: "unknown"}, wantCalls: 1, stage: "plan"},
		{name: "account failed", savedPlan: "plan", bandwidth: 1024, api: bandwidthFixture{plan: "plan", accountErr: providerErr}, stage: "account_bandwidth"},
		{name: "instance failed", savedPlan: "plan", bandwidth: 1024, api: bandwidthFixture{plan: "plan", instanceErr: providerErr}, stage: "instance"},
		{name: "bandwidth failed", savedPlan: "plan", bandwidth: 1024, api: bandwidthFixture{plan: "plan", bandwidthErr: providerErr}, stage: "instance_bandwidth"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := &budgetFixture{updates: map[string]int64{}, shares: map[string]int64{}, codes: map[string]string{}}
			for _, id := range []string{"a", "b"} {
				r.budgets = append(r.budgets, db.ExitBudget{ID: id, Instance: id, Source: "vultr", Enabled: true, PlanID: tt.savedPlan, PlanBandwidth: tt.bandwidth})
			}
			err := refreshBandwidth(context.Background(), r, &tt.api, time.Now())
			if tt.api.plansCalls != tt.wantCalls {
				t.Fatalf("catalog calls = %d, want %d", tt.api.plansCalls, tt.wantCalls)
			}
			if tt.stage == "" {
				if err != nil || r.updates["a"] != 1024_000_000_000 || r.shares["a"] != 500 || r.shares["b"] != 500 {
					t.Fatalf("bad observation: %+v, %v", r, err)
				}
			} else {
				var failure bandwidthRefreshError
				if !errors.As(err, &failure) || failure.stage != tt.stage || r.codes["a"] == "" || r.codes["b"] == "" || len(r.updates) != 0 {
					t.Fatalf("failure not retained: %+v, %v", r, err)
				}
				if tt.name != "unknown" {
					var apiErr cloud.APIError
					if !errors.As(err, &apiErr) || apiErr.Status != 503 {
						t.Fatalf("HTTP status lost: %v", err)
					}
				}
			}
		})
	}
}
