package db

import (
	"context"
	"encoding/json"
	"github.com/NikitaDmitryuk/ultra/internal/quota"
	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
	"github.com/jackc/pgx/v5"
	"gorm.io/gorm/clause"
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
	return r.db.orm.WithContext(ctx).Table("exit_traffic_budgets").Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "exit_id"}}, DoUpdates: clause.AssignmentColumns([]string{"instance_id", "monthly_bytes"})}).Create(map[string]any{"exit_id": id, "instance_id": instance, "monthly_bytes": monthly, "source": "vultr"}).Error
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
		rows, err := tx.Query(ctx, `WITH pool_usage AS (
 SELECT t.account_id,SUM(GREATEST(t.uplink_bytes+t.downlink_bytes,t.charged_bytes))::bigint AS used
 FROM account_exit_usage t JOIN quota_exit_membership m ON m.exit_id=t.exit_id AND m.scope='vultr'
 WHERE t.period=$2 AND $3 GROUP BY t.account_id
 ) SELECT u.uuid::text,COALESCE(GREATEST(t.uplink_bytes+t.downlink_bytes,t.charged_bytes),0)::bigint,
 COALESCE(s.monthly_bytes,0),q.blocked,COALESCE(p.used,0)::bigint
 FROM users u LEFT JOIN account_exit_usage t ON t.account_id=u.account_id AND t.exit_id=$1 AND t.period=$2
 LEFT JOIN service_access s ON s.account_id=u.account_id
 LEFT JOIN user_exit_quotas q ON q.user_uuid=u.uuid AND q.exit_id=$1::uuid
 LEFT JOIN pool_usage p ON p.account_id=u.account_id
 WHERE u.is_active AND u.kind='vless'`, b.ID, month.Format("2006-01"), b.Source == "vultr")
		if err != nil {
			return false, err
		}
		type usage struct {
			ID           string
			Used         int64
			ServiceLimit int64
			OldBlocked   *bool
			PoolUsed     int64
		}
		demand := []usage{}
		for rows.Next() {
			var d usage
			if e = rows.Scan(&d.ID, &d.Used, &d.ServiceLimit, &d.OldBlocked, &d.PoolUsed); e != nil {
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
		type quotaUpdate struct {
			User    string `json:"user_uuid"`
			Used    int64  `json:"used_bytes"`
			Limit   int64  `json:"limit_bytes"`
			Blocked bool   `json:"blocked"`
			Reason  string `json:"reason"`
		}
		updates := make([]quotaUpdate, 0, len(demand))
		for _, d := range demand {
			if b.Source == "vultr" && d.ServiceLimit == 0 {
				d.Used = d.PoolUsed
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
			if d.OldBlocked == nil || *d.OldBlocked != blocked {
				changed = true
			}
			updates = append(updates, quotaUpdate{d.ID, d.Used, limit, blocked, why})
		}
		if len(updates) > 0 {
			raw, err := json.Marshal(updates)
			if err != nil {
				return false, err
			}
			_, e = tx.Exec(ctx, `INSERT INTO user_exit_quotas(user_uuid,exit_id,day,used_bytes,limit_bytes,blocked,reason)
 SELECT v.user_uuid,$2,$3,v.used_bytes,v.limit_bytes,v.blocked,v.reason
 FROM jsonb_to_recordset($1::jsonb) AS v(user_uuid uuid,used_bytes bigint,limit_bytes bigint,blocked boolean,reason text)
 ON CONFLICT(user_uuid,exit_id) DO UPDATE SET day=EXCLUDED.day,used_bytes=EXCLUDED.used_bytes,
 limit_bytes=EXCLUDED.limit_bytes,blocked=EXCLUDED.blocked,reason=EXCLUDED.reason,
 applied=CASE WHEN user_exit_quotas.blocked=EXCLUDED.blocked THEN user_exit_quotas.applied ELSE false END
 WHERE (user_exit_quotas.day,user_exit_quotas.used_bytes,user_exit_quotas.limit_bytes,user_exit_quotas.blocked,user_exit_quotas.reason)
 IS DISTINCT FROM (EXCLUDED.day,EXCLUDED.used_bytes,EXCLUDED.limit_bytes,EXCLUDED.blocked,EXCLUDED.reason)`, raw, b.ID, day)
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
	result := []QuotaSnapshot{}
	err := r.db.orm.WithContext(ctx).Table("user_exit_quotas").Select("user_uuid AS user, exit_id AS exit, day, used_bytes AS used, limit_bytes AS limit, blocked, reason").Where("NOT applied").Find(&result).Error
	return result, err
}
func (r *QuotaRepo) Acknowledge(ctx context.Context, snapshot []QuotaSnapshot) error {
	for _, s := range snapshot {
		err := r.db.orm.WithContext(ctx).Table("user_exit_quotas").Where(map[string]any{"user_uuid": s.User, "exit_id": s.Exit, "day": s.Day, "used_bytes": s.Used, "limit_bytes": s.Limit, "blocked": s.Blocked, "reason": s.Reason}).Update("applied", true).Error
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

// HasAvailableExit reports whether this user has an enabled, unblocked exit.
func (r *QuotaRepo) HasAvailableExit(ctx context.Context, userUUID string) (bool, error) {
	var rows []struct {
		UserUUID string `gorm:"column:user_uuid"`
	}
	err := r.db.orm.WithContext(ctx).Table("user_exit_quotas AS q").Select("q.user_uuid").Joins("JOIN exit_nodes x ON x.id = q.exit_id").Where("q.user_uuid = ? AND NOT q.blocked AND x.enabled", userUUID).Limit(1).Find(&rows).Error
	return len(rows) > 0, err
}
