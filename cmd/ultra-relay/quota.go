package main

import (
	"context"
	"errors"
	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/db"
	"log/slog"
	"math"
	"math/big"
	"time"
)

func runQuotas(ctx context.Context, database *db.DB, api *cloud.Vultr, apply func(context.Context) error, log *slog.Logger) {
	repo := db.NewQuotaRepo(database)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	var nextProvider time.Time
	pending := true
	for {
		// Provider GETs have 20-second timeouts and retry transient failures.
		c, cancel := context.WithTimeout(ctx, 90*time.Second)
		now := time.Now()
		if !now.Before(nextProvider) {
			if e := refreshBandwidth(c, repo, optionalBandwidthAPI(api), now); e != nil {
				var refreshErr bandwidthRefreshError
				var apiErr cloud.APIError
				_ = errors.As(e, &refreshErr)
				_ = errors.As(e, &apiErr)
				log.Warn("quota provider refresh failed", "stage", refreshErr.stage, "code", cloud.ErrorCode(e), "http_status", apiErr.Status)
			}
			nextProvider = now.Add(5 * time.Minute)
		}
		changed, e := repo.Recalculate(c, now)
		pending = pending || changed
		if e == nil && pending {
			e = apply(c)
			if e == nil {
				pending = false
				log.Info("quota routing applied")
			}
		}
		if e != nil {
			log.Warn("quota evaluation failed; retry scheduled", "code", "quota_unavailable")
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type bandwidthRefreshError struct {
	stage string
	err   error
}

func (e bandwidthRefreshError) Error() string { return e.stage + ": bandwidth refresh failed" }
func (e bandwidthRefreshError) Unwrap() error { return e.err }

type bandwidthRepo interface {
	Budgets(context.Context) ([]db.ExitBudget, error)
	SaveBandwidth(context.Context, []db.BandwidthObservation, time.Time) error
}
type bandwidthAPI interface {
	Plans(context.Context) ([]cloud.Plan, error)
	Get(context.Context, string) (cloud.Instance, error)
	AccountRemaining(context.Context) (int64, error)
	InstanceBandwidth(context.Context, string, time.Time) (int64, error)
}

func refreshBandwidth(ctx context.Context, repo bandwidthRepo, api bandwidthAPI, now time.Time) error {
	budgets, e := repo.Budgets(ctx)
	if e != nil {
		return bandwidthRefreshError{stage: "budgets", err: e}
	}
	managed := []db.ExitBudget{}
	for _, b := range budgets {
		if b.Source == "vultr" && b.Enabled {
			managed = append(managed, b)
		}
	}
	if len(managed) == 0 {
		return nil
	}
	var remaining int64
	var plans []cloud.Plan
	if api == nil {
		e = cloud.ErrUnavailable
	} else {
		remaining, e = api.AccountRemaining(ctx)
	}
	accountErr := e
	var plansErr error
	plansLoaded := false
	// Resolve every actual plan before partitioning the account ceiling. Never use
	// instance.allowed_bandwidth as the nominal plan allowance.
	type observation struct {
		budget db.ExitBudget
		used   int64
		err    error
		stage  string
	}
	observations := make([]observation, 0, len(managed))
	var total int64
	for _, b := range managed {
		o := observation{budget: b, err: accountErr, stage: "account_bandwidth"}
		if o.err == nil {
			instance, getErr := api.Get(ctx, b.Instance)
			o.err = getErr
			o.stage = "instance"
			if o.err == nil {
				o.stage = "plan"
				if b.PlanID != "" && b.PlanID == instance.Plan && b.PlanBandwidth > 0 && b.PlanBandwidth <= math.MaxInt64/1_000_000_000 {
					o.budget.Monthly = b.PlanBandwidth * 1_000_000_000
				} else {
					if !plansLoaded {
						plans, plansErr = api.Plans(ctx)
						plansLoaded = true
					}
					o.err = plansErr
					if o.err == nil {
						o.err = cloud.ErrUnavailable
						for _, p := range plans {
							if p.ID == instance.Plan && p.Bandwidth > 0 && int64(p.Bandwidth) <= math.MaxInt64/1_000_000_000 {
								o.budget.Monthly = int64(p.Bandwidth) * 1_000_000_000
								o.err = nil
								break
							}
						}
					}
				}
			}
			if o.err == nil {
				o.stage = "instance_bandwidth"
				o.used, o.err = api.InstanceBandwidth(ctx, b.Instance, now)
			}
		}
		if o.err == nil {
			if o.budget.Monthly > math.MaxInt64-total {
				return bandwidthRefreshError{stage: "plan", err: cloud.ErrUnavailable}
			}
			total += o.budget.Monthly
		}
		observations = append(observations, o)
	}
	updates := make([]db.BandwidthObservation, 0, len(observations))
	for _, o := range observations {
		code := ""
		var share int64
		if o.err != nil {
			code = cloud.ErrorCode(o.err)
			e = bandwidthRefreshError{stage: o.stage, err: o.err}
		} else {
			// Integer arithmetic keeps the sum of rounded-down shares <= remaining.
			amount := new(big.Int).Mul(big.NewInt(max(0, remaining)), big.NewInt(o.budget.Monthly))
			share = amount.Div(amount, big.NewInt(max(1, total))).Int64()

		}
		updates = append(updates, db.BandwidthObservation{ID: o.budget.ID, Instance: o.budget.Instance, Monthly: o.budget.Monthly, Used: o.used, Remaining: share, Error: code})
	}
	if err := repo.SaveBandwidth(ctx, updates, now); err != nil {
		return bandwidthRefreshError{stage: "save_bandwidth", err: err}
	}
	return e
}

func optionalBandwidthAPI(api *cloud.Vultr) bandwidthAPI {
	if api == nil {
		return nil
	}
	return api
}
