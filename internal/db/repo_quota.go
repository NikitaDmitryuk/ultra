package db

import (
	"context"
	"encoding/json"
	"github.com/NikitaDmitryuk/ultra/internal/quota"
	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
	"github.com/jackc/pgx/v5"
	"time"
)

type QuotaRepo struct {
	db    *DB
	state *runtimestate.Store
}

func NewQuotaRepo(d *DB) *QuotaRepo                               { return &QuotaRepo{db: d} }
func NewRuntimeQuotaRepo(d *DB, s *runtimestate.Store) *QuotaRepo { return &QuotaRepo{db: d, state: s} }

type ExitBudget struct {
	Enabled           bool       `json:"enabled"`
	ID                string     `json:"exit_id"`
	Name              string     `json:"name"`
	Instance          string     `json:"-"`
	PlanID            string     `json:"-"`
	PlanBandwidth     int64      `json:"-"`
	Monthly           int64      `json:"monthly_bytes"`
	Source            string     `json:"source"`
	Fallback          bool       `json:"is_fallback"`
	ProviderUsed      int64      `json:"provider_used_bytes"`
	Remaining         int64      `json:"provider_remaining_bytes"`
	Observed          *time.Time `json:"observed_at"`
	Error             string     `json:"error"`
	EmergencyStarted  *time.Time `json:"-"`
	EmergencyBaseline *int64     `json:"-"`
	ObservedLocal     int64      `json:"-"`
}

func (r *QuotaRepo) Budgets(ctx context.Context) ([]ExitBudget, error) {
	rows, e := r.db.Pool.Query(ctx, `SELECT n.enabled,b.exit_id::text,COALESCE(NULLIF(n.display_name,''),NULLIF(n.city,''),n.name),b.instance_id,b.monthly_bytes,b.source,b.is_fallback,b.provider_used_bytes,b.account_remaining_bytes,b.observed_at,b.provider_error,b.emergency_started_at,b.emergency_baseline_bytes,b.provider_observed_local_bytes,COALESCE(op.body->'offer'->'plan','{}'::jsonb)
 FROM exit_traffic_budgets b JOIN exit_nodes n ON n.id=b.exit_id
 LEFT JOIN LATERAL (
 SELECT body FROM cloud_operations WHERE state='ready'
 AND body->>'instance_id'=b.instance_id AND body->>'exit_id'=b.exit_id::text
 ORDER BY created_at DESC,id DESC LIMIT 1
 ) op ON true ORDER BY n.priority,n.id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []ExitBudget{}
	for rows.Next() {
		var b ExitBudget
		var planJSON []byte
		if e = rows.Scan(&b.Enabled, &b.ID, &b.Name, &b.Instance, &b.Monthly, &b.Source, &b.Fallback, &b.ProviderUsed, &b.Remaining, &b.Observed, &b.Error, &b.EmergencyStarted, &b.EmergencyBaseline, &b.ObservedLocal, &planJSON); e != nil {
			return nil, e
		}
		var plan struct {
			ID        string `json:"id"`
			Bandwidth int64  `json:"bandwidth"`
		}
		if json.Unmarshal(planJSON, &plan) == nil {
			b.PlanID, b.PlanBandwidth = plan.ID, plan.Bandwidth
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
func (r *QuotaRepo) EnsureVultr(ctx context.Context, id, instance string, monthly int64) error {
	_, e := r.db.Pool.Exec(ctx, `INSERT INTO exit_traffic_budgets(exit_id,instance_id,monthly_bytes,source) VALUES($1,$2,$3,'vultr') ON CONFLICT(exit_id) DO UPDATE SET instance_id=EXCLUDED.instance_id,monthly_bytes=EXCLUDED.monthly_bytes`, id, instance, monthly)
	return e
}

// Recalculate persists monthly allowances. Only changed exclusions require applying Xray.
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
	changed := false
	pool, e := loadProviderPool(ctx, tx, now)
	if e != nil {
		return false, e
	}
	for _, b := range budgets {
		if !b.Enabled {
			continue
		}
		var used int64
		e = tx.QueryRow(ctx, `SELECT COALESCE(SUM(GREATEST(uplink_bytes+downlink_bytes,charged_bytes)),0)::bigint FROM account_exit_usage WHERE exit_id=$1 AND period=$2`, b.ID, month.Format("2006-01")).Scan(&used)
		if e != nil {
			return false, e
		}
		var remaining int64
		var reason string
		monthly := b.Monthly
		if b.Source == "vultr" {
			monthly = pool.Accrued
			remaining, reason, e = effectivePoolExitRemaining(ctx, tx, b, pool, used, now)
		} else {
			remaining, reason, e = effectiveExitRemaining(ctx, tx, b, used, now)
		}
		if e != nil {
			return false, e
		}
		if remaining == 0 && reason == "" {
			reason = "exit_budget_exhausted"
		}
		rows, err := tx.Query(ctx, `SELECT u.uuid::text,COALESCE(MAX(GREATEST(t.uplink_bytes+t.downlink_bytes,t.charged_bytes)),0)::bigint, COALESCE((SELECT monthly_bytes FROM service_access s WHERE s.account_id=u.account_id),0) FROM users u LEFT JOIN account_exit_usage t ON t.account_id=u.account_id AND t.exit_id=$1 AND t.period=$2 WHERE u.is_active AND u.kind='vless' GROUP BY u.uuid`, b.ID, month.Format("2006-01"))
		if err != nil {
			return false, err
		}
		type usage struct {
			ID           string
			Used         int64
			ServiceLimit int64
		}
		demand := []usage{}
		for rows.Next() {
			var d usage
			if e = rows.Scan(&d.ID, &d.Used, &d.ServiceLimit); e != nil {
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
		for _, d := range demand {
			if b.Source == "vultr" && d.ServiceLimit == 0 {
				var account string
				if e = tx.QueryRow(ctx, `SELECT account_id::text FROM users WHERE uuid=$1`, d.ID).Scan(&account); e != nil {
					return false, e
				}
				d.Used, e = poolUsage(ctx, tx, month.Format("2006-01"), account)
				if e != nil {
					return false, e
				}
			}
			limit := d.Used + quota.Available(monthly, d.Used, remaining, (b.Fallback && b.Source != "vultr") || d.ServiceLimit > 0)
			if d.ServiceLimit > 0 && limit > d.ServiceLimit {
				limit = d.ServiceLimit
			}
			blocked := remaining == 0 || d.Used >= limit
			why := reason
			if blocked && why == "" {
				why = "monthly_user_limit_exhausted"
				if d.ServiceLimit > 0 {
					why = "monitor_quota_exhausted"
				}
			}
			var old *bool
			e = tx.QueryRow(ctx, `SELECT (SELECT blocked FROM user_exit_quotas WHERE user_uuid=$1 AND exit_id=$2)`, d.ID, b.ID).Scan(&old)
			if e != nil {
				return false, e
			}
			if old == nil || *old != blocked {
				changed = true
			}
			_, e = tx.Exec(ctx, `INSERT INTO user_exit_quotas(user_uuid,exit_id,day,used_bytes,limit_bytes,blocked,reason) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(user_uuid,exit_id) DO UPDATE SET day=EXCLUDED.day,used_bytes=EXCLUDED.used_bytes,limit_bytes=EXCLUDED.limit_bytes,blocked=EXCLUDED.blocked,reason=EXCLUDED.reason,applied=CASE WHEN user_exit_quotas.blocked=EXCLUDED.blocked THEN user_exit_quotas.applied ELSE false END`, d.ID, b.ID, day, d.Used, limit, blocked, why)
			if e != nil {
				return false, e
			}
		}
	}
	var pending bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_exit_quotas WHERE NOT applied)`).Scan(&pending); e != nil {
		return false, e
	}
	return changed || pending, tx.Commit(ctx)
}

// Snapshot makes acknowledgement conditional on the exact calculation applied.
type QuotaSnapshot struct {
	User, Exit  string
	Day         time.Time
	Used, Limit int64
	Blocked     bool
	Reason      string
}

func (r *QuotaRepo) Snapshot(ctx context.Context) ([]QuotaSnapshot, error) {
	rows, err := r.db.Pool.Query(ctx, `SELECT user_uuid::text,exit_id::text,day,used_bytes,limit_bytes,blocked,reason FROM user_exit_quotas WHERE NOT applied`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []QuotaSnapshot{}
	for rows.Next() {
		var s QuotaSnapshot
		if err = rows.Scan(&s.User, &s.Exit, &s.Day, &s.Used, &s.Limit, &s.Blocked, &s.Reason); err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, rows.Err()
}
func (r *QuotaRepo) Acknowledge(ctx context.Context, snapshot []QuotaSnapshot) error {
	for _, s := range snapshot {
		_, err := r.db.Pool.Exec(ctx, `UPDATE user_exit_quotas SET applied=true WHERE user_uuid=$1 AND exit_id=$2 AND day=$3 AND used_bytes=$4 AND limit_bytes=$5 AND blocked=$6 AND reason=$7`, s.User, s.Exit, s.Day, s.Used, s.Limit, s.Blocked, s.Reason)
		if err != nil {
			return err
		}
	}
	return nil
}

// BandwidthObservation is one provider refresh, committed with the other nodes.
type BandwidthObservation struct {
	ID, Instance                         string
	Monthly, Used, Remaining             int64
	Accrued, AccountUsed, LocalWatermark int64
	Pool                                 bool
	Error                                string
}

func (r *QuotaRepo) SaveBandwidth(ctx context.Context, observations []BandwidthObservation, now time.Time) error {
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	for _, o := range observations {
		if o.Pool {
			period := now.UTC().Format("2006-01")
			if o.Error != "" {
				_, err = tx.Exec(ctx, `UPDATE provider_quota_pools SET provider_error=$2 WHERE scope='vultr' AND period=$1`, period, o.Error)
			} else {
				_, err = tx.Exec(ctx, `INSERT INTO provider_quota_pools(scope,period,accrued_bytes,provider_used_bytes,remaining_bytes,observed_local_bytes,observed_at) VALUES('vultr',$1,$2,$3,$4,$5,$6) ON CONFLICT(scope,period) DO UPDATE SET accrued_bytes=EXCLUDED.accrued_bytes,provider_used_bytes=EXCLUDED.provider_used_bytes,remaining_bytes=EXCLUDED.remaining_bytes,observed_local_bytes=EXCLUDED.observed_local_bytes,observed_at=EXCLUDED.observed_at,provider_error='' WHERE provider_quota_pools.observed_at<=EXCLUDED.observed_at`, period, o.Accrued, o.AccountUsed, o.Remaining, o.LocalWatermark, now)
			}
			if err != nil {
				return err
			}
		}
		if o.Error != "" {
			_, err = tx.Exec(ctx, `UPDATE exit_traffic_budgets SET provider_error=$2,updated_at=$3 WHERE exit_id=$1`, o.ID, o.Error, now)
		} else {
			_, err = tx.Exec(ctx, `UPDATE exit_traffic_budgets SET monthly_bytes=$2,provider_used_bytes=$3,account_remaining_bytes=$4,observed_at=$5,updated_at=$5,provider_error='',emergency_started_at=NULL,emergency_baseline_bytes=NULL,provider_observed_local_bytes=(SELECT COALESCE(SUM(GREATEST(uplink_bytes+downlink_bytes,charged_bytes)),0)::bigint FROM account_exit_usage WHERE exit_id=$1::text AND period=to_char($5::timestamptz AT TIME ZONE 'UTC','YYYY-MM')) WHERE exit_id=$1 AND instance_id=$6`, o.ID, o.Monthly, o.Used, o.Remaining, now, o.Instance)
		}
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

const EmergencyBytes int64 = 5_000_000_000

func effectiveExitRemaining(_ context.Context, _ pgx.Tx, b ExitBudget, used int64, _ time.Time) (int64, string, error) {
	if b.Source != "manual" {
		return 0, "provider_pool_required", nil
	}
	return max(0, quota.SafeBudget(b.Monthly)-used), "", nil
}

// RuntimeLimits returns cumulative allowances. A single bridge retains the greater
// of this confirmed spend and its durable local reservations on every refresh.
func (r *QuotaRepo) RuntimeLimits(ctx context.Context, now time.Time) ([]runtimestate.QuotaLimit, error) {
	budgets, e := r.Budgets(ctx)
	if e != nil {
		return nil, e
	}
	tx, e := r.db.Pool.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	now = now.UTC()
	period := now.Format("2006-01")
	expires := minTime(now.Add(runtimestate.SnapshotTTL), time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC))
	out, e := r.poolRuntimeLimits(ctx, tx, budgets, now, expires)
	if e != nil {
		return nil, e
	}
	for _, b := range budgets {
		if !b.Enabled || b.Source == "vultr" {
			continue
		}
		var used int64
		if e = tx.QueryRow(ctx, `SELECT COALESCE(SUM(GREATEST(uplink_bytes+downlink_bytes,charged_bytes)),0)::bigint FROM account_exit_usage WHERE exit_id=$1 AND period=$2`, b.ID, period).Scan(&used); e != nil {
			return nil, e
		}
		left, _, e := effectiveExitRemaining(ctx, tx, b, used, now)
		if e != nil {
			return nil, e
		}
		deadline := expires
		global := runtimestate.QuotaLimit{ExitID: b.ID, Period: period, LimitBytes: used + left, UsedBytes: used, ExpiresAt: deadline}
		out = append(out, global)
		rows, e := tx.Query(ctx, `SELECT u.account_id::text,q.limit_bytes,q.used_bytes,q.blocked FROM user_exit_quotas q JOIN users u ON u.uuid=q.user_uuid WHERE q.exit_id=$1 AND u.is_active AND NOT u.member_pending`, b.ID)
		if e != nil {
			return nil, e
		}
		for rows.Next() {
			var account string
			var limit, consumed int64
			var blocked bool
			if e = rows.Scan(&account, &limit, &consumed, &blocked); e != nil {
				rows.Close()
				return nil, e
			}
			if blocked {
				limit = consumed
			}
			out = append(out, runtimestate.QuotaLimit{AccountID: account, ExitID: b.ID, Period: period, LimitBytes: limit, UsedBytes: consumed, ExpiresAt: deadline})
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, e
		}
	}
	if e = tx.Commit(ctx); e != nil {
		return nil, e
	}
	return out, nil
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
