package main

import (
	"context"
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
		c, cancel := context.WithTimeout(ctx, 25*time.Second)
		now := time.Now()
		if !now.Before(nextProvider) {
			if e := refreshBandwidth(c, repo, api, now); e != nil {
				log.Warn("quota provider refresh failed", "code", cloud.ErrorCode(e))
			}
			nextProvider = now.Add(5 * time.Minute)
		}
		changed, e := repo.Recalculate(c, now)
		pending = pending || changed
		if e == nil && pending {
			e = apply(c)
			if e == nil {
				e = repo.Acknowledge(c)
				pending = e != nil
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
func refreshBandwidth(ctx context.Context, repo *db.QuotaRepo, api *cloud.Vultr, now time.Time) error {
	budgets, e := repo.Budgets(ctx)
	if e != nil {
		return e
	}
	managed := []db.ExitBudget{}
	var total int64
	for _, b := range budgets {
		if b.Source == "vultr" {
			managed = append(managed, b)
			total += b.Monthly
		}
	}
	if len(managed) == 0 {
		return nil
	}
	var remaining int64
	if api == nil {
		e = cloud.ErrUnavailable
	} else {
		remaining, e = api.AccountRemaining(ctx)
	}
	accountErr := e
	for _, b := range managed {
		var used int64
		err := accountErr
		if err == nil {
			instance, getErr := api.Get(ctx, b.Instance)
			err = getErr
			if err == nil {
				if instance.AllowedBandwidth <= 0 {
					err = cloud.ErrUnavailable
				} else {
					err = repo.EnsureVultr(ctx, b.ID, b.Instance, instance.AllowedBandwidth*1_000_000_000)
				}
			}
			if err == nil {
				used, err = api.InstanceBandwidth(ctx, b.Instance, now)
			}
		}
		code := ""
		if err != nil {
			code = cloud.ErrorCode(err)
			e = err
		}
		// Partition the account ceiling between exits. User demand is allocated independently.
		share := int64(float64(remaining) * float64(b.Monthly) / float64(max(1, total)))
		if writeErr := repo.Observe(ctx, b.ID, used, share, code, now); writeErr != nil {
			return writeErr
		}
	}
	return e
}
