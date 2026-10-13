package main

import (
	"context"
	"errors"
	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/db"
	"log/slog"
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
	ProviderWatermark(context.Context, time.Time) (int64, error)
	SaveBandwidth(context.Context, []db.BandwidthObservation, time.Time) error
}
type bandwidthAPI interface {
	AccountBandwidth(context.Context) (cloud.AccountBandwidth, error)
}

func refreshBandwidth(ctx context.Context, repo bandwidthRepo, api bandwidthAPI, now time.Time) error {
	budgets, err := repo.Budgets(ctx)
	if err != nil {
		return bandwidthRefreshError{stage: "budgets", err: err}
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
	watermark, err := repo.ProviderWatermark(ctx, now)
	if err != nil {
		return bandwidthRefreshError{stage: "membership", err: err}
	}
	var pool cloud.AccountBandwidth
	if api == nil {
		err = cloud.ErrUnavailable
	} else {
		pool, err = api.AccountBandwidth(ctx)
	}
	if err == nil && (pool.Accrued < 0 || pool.Used < 0 || pool.Remaining < 0) {
		err = cloud.ErrUnavailable
	}
	updates := make([]db.BandwidthObservation, 0, len(managed))
	for _, b := range managed {
		code := ""
		if err != nil {
			code = cloud.ErrorCode(err)
		}
		// Every exit refers to this same observation. There are no apportioned shares
		// and no dependency on a nominal plan or individual instance statistics.
		updates = append(updates, db.BandwidthObservation{ID: b.ID, Instance: b.Instance, Monthly: b.Monthly, Remaining: pool.Remaining, Accrued: pool.Accrued, AccountUsed: pool.Used, LocalWatermark: watermark, Pool: true, Error: code})
	}
	if saveErr := repo.SaveBandwidth(ctx, updates, now); saveErr != nil {
		return bandwidthRefreshError{stage: "save_bandwidth", err: saveErr}
	}
	if err != nil {
		return bandwidthRefreshError{stage: "account_bandwidth", err: err}
	}
	return nil
}

func optionalBandwidthAPI(api *cloud.Vultr) bandwidthAPI {
	if api == nil {
		return nil
	}
	return api
}
