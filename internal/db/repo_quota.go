package db

import (
	"context"
	"github.com/NikitaDmitryuk/ultra/internal/quota"
	"time"
)

type QuotaRepo struct{ db *DB }

func NewQuotaRepo(d *DB) *QuotaRepo { return &QuotaRepo{db: d} }

type ExitBudget struct {
	Enabled      bool       `json:"enabled"`
	ID           string     `json:"exit_id"`
	Name         string     `json:"name"`
	Instance     string     `json:"-"`
	Monthly      int64      `json:"monthly_bytes"`
	Source       string     `json:"source"`
	Fallback     bool       `json:"is_fallback"`
	ProviderUsed int64      `json:"provider_used_bytes"`
	Remaining    int64      `json:"provider_remaining_bytes"`
	Observed     *time.Time `json:"observed_at"`
	Error        string     `json:"error"`
}

func (r *QuotaRepo) Budgets(ctx context.Context) ([]ExitBudget, error) {
	rows, e := r.db.Pool.Query(ctx, `SELECT n.enabled,b.exit_id::text,COALESCE(NULLIF(n.display_name,''),NULLIF(n.city,''),n.name),b.instance_id,b.monthly_bytes,b.source,b.is_fallback,b.provider_used_bytes,b.account_remaining_bytes,b.observed_at,b.provider_error FROM exit_traffic_budgets b JOIN exit_nodes n ON n.id=b.exit_id ORDER BY n.priority,n.id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []ExitBudget{}
	for rows.Next() {
		var b ExitBudget
		if e = rows.Scan(&b.Enabled, &b.ID, &b.Name, &b.Instance, &b.Monthly, &b.Source, &b.Fallback, &b.ProviderUsed, &b.Remaining, &b.Observed, &b.Error); e != nil {
			return nil, e
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
func (r *QuotaRepo) EnsureVultr(ctx context.Context, id, instance string, monthly int64) error {
	_, e := r.db.Pool.Exec(ctx, `INSERT INTO exit_traffic_budgets(exit_id,instance_id,monthly_bytes,source) VALUES($1,$2,$3,'vultr') ON CONFLICT(exit_id) DO UPDATE SET instance_id=EXCLUDED.instance_id,monthly_bytes=EXCLUDED.monthly_bytes`, id, instance, monthly)
	return e
}
func (r *QuotaRepo) Observe(ctx context.Context, id string, used, remaining int64, code string, now time.Time) error {
	if code != "" {
		_, e := r.db.Pool.Exec(ctx, `UPDATE exit_traffic_budgets SET provider_error=$2,updated_at=$3 WHERE exit_id=$1`, id, code, now)
		return e
	}
	_, e := r.db.Pool.Exec(ctx, `UPDATE exit_traffic_budgets SET provider_used_bytes=$2,account_remaining_bytes=$3,observed_at=$4,updated_at=$4,provider_error='' WHERE exit_id=$1`, id, used, remaining, now)
	return e
}

// Recalculate persists daily allowances. Only changed exclusions require applying Xray.
func (r *QuotaRepo) Recalculate(ctx context.Context, now time.Time) (bool, error) {
	budgets, e := r.Budgets(ctx)
	if e != nil {
		return false, e
	}
	tx, e := r.db.Pool.Begin(ctx)
	if e != nil {
		return false, e
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(817365009)`); e != nil {
		return false, e
	}
	now = now.UTC()
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := month.AddDate(0, 1, 0)
	daysLeft := int64(end.Sub(day).Hours() / 24)
	changed := false
	for _, b := range budgets {
		if !b.Enabled {
			continue
		}
		tag := "to-exit-" + b.ID
		var used, today int64
		e = tx.QueryRow(ctx, `SELECT COALESCE(SUM(uplink_bytes+downlink_bytes),0)::bigint,COALESCE(SUM(uplink_bytes+downlink_bytes) FILTER(WHERE day=$3),0)::bigint FROM daily_route_traffic WHERE exit_tag=$1 AND day>=$2 AND day<$4`, tag, month, day, end).Scan(&used, &today)
		if e != nil {
			return false, e
		}
		remaining := max(0, b.Monthly-b.Monthly/5-used)
		reason := ""
		if b.Source == "vultr" {
			if b.Observed == nil || now.Sub(*b.Observed) > 15*time.Minute || b.Observed.Before(month) || b.Error != "" {
				remaining = 0
				reason = "provider_unavailable"
			} else {
				remaining = min(remaining, b.Remaining, max(0, b.Monthly-b.Monthly/5-b.ProviderUsed))
			}
		}
		if remaining == 0 && reason == "" {
			reason = "exit_budget_exhausted"
		}
		pool := (remaining + today) / max(1, daysLeft)
		rows, err := tx.Query(ctx, `SELECT u.uuid::text,COALESCE(SUM(t.uplink_bytes+t.downlink_bytes) FILTER(WHERE t.day=$2),0)::bigint,COALESCE(SUM(t.uplink_bytes+t.downlink_bytes) FILTER(WHERE t.day<$2),0)::bigint FROM users u LEFT JOIN daily_route_traffic t ON t.user_uuid=u.uuid AND t.exit_tag=$1 AND t.day>=$3 AND t.day<=$2 WHERE u.is_active AND u.kind='vless' GROUP BY u.uuid`, tag, day, day.AddDate(0, 0, -7))
		if err != nil {
			return false, err
		}
		demand := []quota.Demand{}
		for rows.Next() {
			var d quota.Demand
			if e = rows.Scan(&d.ID, &d.Today, &d.Recent); e != nil {
				rows.Close()
				return false, e
			}
			demand = append(demand, d)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return false, e
		}
		allocation := quota.Allocate(pool, demand)
		for _, d := range demand {
			limit := allocation[d.ID]
			if b.Fallback {
				limit = d.Today + remaining
			}
			blocked := remaining == 0 || d.Today >= limit
			why := reason
			if blocked && why == "" {
				why = "daily_allowance_exhausted"
			}
			var old *bool
			e = tx.QueryRow(ctx, `SELECT (SELECT blocked FROM user_exit_quotas WHERE user_uuid=$1 AND exit_id=$2)`, d.ID, b.ID).Scan(&old)
			if e != nil {
				return false, e
			}
			if old == nil || *old != blocked {
				changed = true
			}
			_, e = tx.Exec(ctx, `INSERT INTO user_exit_quotas(user_uuid,exit_id,day,used_bytes,limit_bytes,blocked,reason) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(user_uuid,exit_id) DO UPDATE SET day=EXCLUDED.day,used_bytes=EXCLUDED.used_bytes,limit_bytes=EXCLUDED.limit_bytes,blocked=EXCLUDED.blocked,reason=EXCLUDED.reason,applied=CASE WHEN user_exit_quotas.blocked=EXCLUDED.blocked THEN user_exit_quotas.applied ELSE false END`, d.ID, b.ID, day, d.Today, limit, blocked, why)
			if e != nil {
				return false, e
			}
		}
	}
	return changed, tx.Commit(ctx)
}

func (r *QuotaRepo) Acknowledge(ctx context.Context) error {
	_, e := r.db.Pool.Exec(ctx, `UPDATE user_exit_quotas SET applied=true WHERE NOT applied`)
	return e
}
