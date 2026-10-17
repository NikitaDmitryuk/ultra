package db

import (
	"context"
	"errors"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/quota"
	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
	"github.com/jackc/pgx/v5"
)

// PoolQuota exposes a single owner's ceiling; physical route statistics stay separate.
type PoolQuota struct {
	Scope         string     `json:"scope"`
	Period        string     `json:"period"`
	PersonalLimit int64      `json:"personal_limit_bytes"`
	Used          int64      `json:"used_bytes"`
	Remaining     int64      `json:"remaining_bytes"`
	ObservedAt    *time.Time `json:"observed_at"`
	State         string     `json:"state"`
	ResetsAt      time.Time  `json:"resets_at"`
}

type providerPool struct {
	Accrued, ProviderUsed, Remaining, ObservedLocal, Used int64
	Observed                                              *time.Time
	Error                                                 string
}

// Unknown physical routes cannot be excluded silently from the shared pool.
func validatePoolMembership(ctx context.Context, tx pgx.Tx, period string) error {
	var unknown bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM account_exit_usage u LEFT JOIN quota_exit_membership m ON m.exit_id=u.exit_id WHERE u.period=$1 AND u.exit_id NOT IN ('','direct','block') AND GREATEST(u.uplink_bytes+u.downlink_bytes,u.charged_bytes)>0 AND m.exit_id IS NULL)`, period).
		Scan(&unknown)
	if err != nil {
		return err
	}
	if unknown {
		return errors.New("unclassified historical quota route")
	}
	return nil
}

func poolUsage(ctx context.Context, tx pgx.Tx, period, account string) (int64, error) {
	var used int64
	err := tx.QueryRow(ctx, `SELECT COALESCE(SUM(GREATEST(u.uplink_bytes+u.downlink_bytes,u.charged_bytes)),0)::bigint FROM account_exit_usage u JOIN quota_exit_membership m ON m.exit_id=u.exit_id AND m.scope='vultr' WHERE u.period=$1 AND ($2='' OR u.account_id::text=$2)`, period, account).
		Scan(&used)
	return used, err
}

func loadProviderPool(ctx context.Context, tx pgx.Tx, now time.Time) (providerPool, error) {
	var p providerPool
	period := now.UTC().Format("2006-01")
	var enabled bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM quota_exit_membership WHERE scope='vultr')`).Scan(&enabled); err != nil {
		return p, err
	}
	if !enabled {
		return p, nil
	}
	if err := validatePoolMembership(ctx, tx, period); err != nil {
		return p, err
	}
	err := tx.QueryRow(ctx, `SELECT accrued_bytes,provider_used_bytes,remaining_bytes,observed_local_bytes,observed_at,provider_error FROM provider_quota_pools WHERE scope='vultr' AND period=$1`, period).
		Scan(&p.Accrued, &p.ProviderUsed, &p.Remaining, &p.ObservedLocal, &p.Observed, &p.Error)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return p, err
	}
	p.Used, err = poolUsage(ctx, tx, period, "")
	return p, err
}

func (p providerPool) available(now time.Time) int64 {
	if p.Observed == nil || now.Before(p.Observed.Add(-time.Minute)) || !now.Before(p.Observed.Add(24*time.Hour)) ||
		p.Observed.UTC().Format("2006-01") != now.UTC().Format("2006-01") {
		return 0
	}
	// The local watermark is captured before the provider request, not on receipt.
	since := max(0, p.Used-p.ObservedLocal)
	return max(0, min(quota.SafeBudget(p.Accrued)-p.Used, p.Remaining-since))
}

func (r *QuotaRepo) SubscriptionQuota(ctx context.Context, account string, now time.Time) (PoolQuota, error) {
	q := PoolQuota{
		Scope:    "vultr",
		Period:   now.UTC().Format("2006-01"),
		State:    "unknown",
		ResetsAt: time.Date(now.UTC().Year(), now.UTC().Month()+1, 1, 0, 0, 0, 0, time.UTC),
	}
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return q, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var exists bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM quota_exit_membership WHERE scope='vultr')`).Scan(&exists)
	if err != nil {
		return q, err
	}
	if !exists {
		return PoolQuota{}, tx.Commit(ctx)
	}
	p, err := loadProviderPool(ctx, tx, now)
	if err != nil {
		return q, err
	}
	q.ObservedAt = p.Observed
	q.PersonalLimit = quota.PersonalLimit(p.Accrued)
	q.Used, err = poolUsage(ctx, tx, q.Period, account)
	if err != nil {
		return q, err
	}
	if r.state != nil {
		personal, global, localErr := r.state.PoolUsage(account, "vultr")
		if localErr == nil {
			q.Used = max(q.Used, personal)
			p.Used = max(p.Used, global)
		}
	}
	available := int64(0)
	// Advertise only budget usable through at least one enabled, confirmed exit.
	budgets, err := r.Budgets(ctx)
	if err != nil {
		return q, err
	}
	for _, b := range budgets {
		if b.Source != "vultr" || !b.Enabled {
			continue
		}
		var used int64
		err = tx.QueryRow(ctx, `SELECT COALESCE(SUM(GREATEST(uplink_bytes+downlink_bytes,charged_bytes)),0)::bigint FROM account_exit_usage WHERE exit_id=$1 AND period=$2`, b.ID, q.Period).
			Scan(&used)
		if err != nil {
			return q, err
		}
		left, _, err := effectivePoolExitRemaining(ctx, tx, b, p, used, now)
		if err != nil {
			return q, err
		}
		if r.state != nil {
			localLeft, localErr := r.state.Remaining(account, b.ID)
			if localErr != nil {
				left = 0
			} else {
				left = min(left, localLeft)
			}
		}
		available = max(available, left)
	}
	q.Remaining = max(0, min(q.PersonalLimit-q.Used, available))
	if p.Observed != nil && now.Before(p.Observed.Add(24*time.Hour)) && !now.Before(p.Observed.Add(-time.Minute)) {
		q.State = "available"
		if p.Error != "" || now.Sub(*p.Observed) > 15*time.Minute {
			q.State = "emergency"
		}
		if q.Remaining == 0 {
			q.State = "exhausted"
		}
	}
	return q, tx.Commit(ctx)
}

// ProviderWatermark must be obtained before making the external observation.
func (r *QuotaRepo) ProviderWatermark(ctx context.Context, now time.Time) (int64, error) {
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err = validatePoolMembership(ctx, tx, now.UTC().Format("2006-01")); err != nil {
		return 0, err
	}
	used, err := poolUsage(ctx, tx, now.UTC().Format("2006-01"), "")
	if err != nil {
		return 0, err
	}
	return used, tx.Commit(ctx)
}

// Per-exit emergency capacity is a second bound, never another provider pool.
func effectivePoolExitRemaining(
	ctx context.Context,
	tx pgx.Tx,
	b ExitBudget,
	p providerPool,
	used int64,
	now time.Time,
) (int64, string, error) {
	remaining := p.available(now)
	if p.Observed == nil || b.Observed == nil || b.Observed.UTC().Format("2006-01") != now.UTC().Format("2006-01") ||
		!now.Before(b.Observed.Add(24*time.Hour)) ||
		now.Before(b.Observed.Add(-time.Minute)) {
		return 0, "provider_unavailable", nil
	}
	if b.Error == "" && p.Error == "" && now.Sub(*b.Observed) <= 15*time.Minute && now.Sub(*p.Observed) <= 15*time.Minute {
		return remaining, "", nil
	}
	baseline := used
	if b.EmergencyBaseline != nil {
		baseline = *b.EmergencyBaseline
	} else {
		if _, err := tx.Exec(ctx, `UPDATE exit_traffic_budgets SET emergency_started_at=COALESCE(emergency_started_at,$2),emergency_baseline_bytes=COALESCE(emergency_baseline_bytes,$3) WHERE exit_id=$1`, b.ID, now, used); err != nil {
			return 0, "", err
		}
	}
	remaining = min(remaining, max(0, EmergencyBytes-max(0, used-baseline)))
	if remaining == 0 {
		return 0, "provider_emergency_exhausted", nil
	}
	return remaining, "", nil
}

func (r *QuotaRepo) poolRuntimeLimits(
	ctx context.Context,
	tx pgx.Tx,
	budgets []ExitBudget,
	now, expires time.Time,
) ([]runtimestate.QuotaLimit, error) {
	out := []runtimestate.QuotaLimit{}
	p, err := loadProviderPool(ctx, tx, now)
	if err != nil {
		return nil, err
	}
	period := now.UTC().Format("2006-01")
	deadline := expires
	if p.Observed != nil {
		deadline = minTime(deadline, p.Observed.Add(24*time.Hour))
	}
	// Keep disabled/deleted membership in the local snapshot for migration of older charges.
	rows, err := tx.Query(ctx, `SELECT exit_id FROM quota_exit_membership WHERE scope='vultr'`)
	if err != nil {
		return nil, err
	}
	members := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		members = append(members, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(members) == 0 {
		return out, nil
	}
	// Supply every DB physical pair, including revoked owners and removed exits.
	// They are expired migration records, never authorization for those routes.
	rows, err = tx.Query(
		ctx,
		`SELECT u.account_id::text,u.exit_id,GREATEST(u.uplink_bytes+u.downlink_bytes,u.charged_bytes) FROM account_exit_usage u JOIN quota_exit_membership m ON m.exit_id=u.exit_id AND m.scope='vultr' WHERE u.period=$1`,
		period,
	)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var account, id string
		var used int64
		if err = rows.Scan(&account, &id, &used); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(
			out,
			runtimestate.QuotaLimit{
				ChargeOnly: true,
				AccountID:  account,
				PoolScope:  "vultr",
				ExitID:     id,
				Period:     period,
				UsedBytes:  used,
				LimitBytes: used,
			},
		)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	poolID := runtimestate.ProviderPoolID("vultr")
	out = append(
		out,
		runtimestate.QuotaLimit{
			Scope:      "provider_pool",
			ExitID:     poolID,
			Period:     period,
			UsedBytes:  p.Used,
			LimitBytes: p.Used + p.available(now),
			ExpiresAt:  deadline,
			Members:    members,
		},
	)
	type owner struct {
		ID           string
		Used, Limit  int64
		ServiceLimit int64
	}
	owners := []owner{}
	rows, err = tx.Query(
		ctx,
		`SELECT u.account_id::text,COALESCE(s.monthly_bytes,0) FROM users u LEFT JOIN service_access s ON s.account_id=u.account_id WHERE u.is_active AND NOT u.member_pending AND u.kind='vless'`,
	)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var o owner
		if err = rows.Scan(&o.ID, &o.Limit); err != nil {
			rows.Close()
			return nil, err
		}
		owners = append(owners, o)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for i := range owners {
		o := &owners[i]
		o.Used, err = poolUsage(ctx, tx, period, o.ID)
		if err != nil {
			return nil, err
		}
		if o.Limit == 0 {
			o.Limit = quota.PersonalLimit(p.Accrued)
		} else {
			o.ServiceLimit = o.Limit
			o.Limit = quota.SafeBudget(p.Accrued)
		}
		out = append(
			out,
			runtimestate.QuotaLimit{
				Scope:      "provider_pool",
				AccountID:  o.ID,
				ExitID:     poolID,
				Period:     period,
				UsedBytes:  o.Used,
				LimitBytes: o.Limit,
				ExpiresAt:  deadline,
			},
		)
	}
	for _, b := range budgets {
		if !b.Enabled || b.Source != "vultr" {
			continue
		}
		var used int64
		err = tx.QueryRow(ctx, `SELECT COALESCE(SUM(GREATEST(uplink_bytes+downlink_bytes,charged_bytes)),0)::bigint FROM account_exit_usage WHERE exit_id=$1 AND period=$2`, b.ID, period).
			Scan(&used)
		if err != nil {
			return nil, err
		}
		left, _, err := effectivePoolExitRemaining(ctx, tx, b, p, used, now)
		if err != nil {
			return nil, err
		}
		exitDeadline := deadline
		if b.Observed != nil {
			exitDeadline = minTime(exitDeadline, b.Observed.Add(24*time.Hour))
		}
		global := runtimestate.QuotaLimit{
			PoolScope:  "vultr",
			ExitID:     b.ID,
			Period:     period,
			UsedBytes:  used,
			LimitBytes: used + left,
			ExpiresAt:  exitDeadline,
		}
		if b.Observed != nil {
			global.EmergencyAfter = b.Observed.Add(15 * time.Minute)
			global.EmergencyBytes = EmergencyBytes
		}
		out = append(out, global)
		for _, o := range owners {
			var physical int64
			err = tx.QueryRow(ctx, `SELECT COALESCE(MAX(GREATEST(uplink_bytes+downlink_bytes,charged_bytes)),0)::bigint FROM account_exit_usage WHERE exit_id=$1 AND period=$2 AND account_id=$3`, b.ID, period, o.ID).
				Scan(&physical)
			if err != nil {
				return nil, err
			}
			personalLeft := o.Limit - o.Used
			if o.ServiceLimit > 0 {
				personalLeft = min(personalLeft, o.ServiceLimit-physical)
			}
			out = append(
				out,
				runtimestate.QuotaLimit{
					PoolScope:  "vultr",
					AccountID:  o.ID,
					ExitID:     b.ID,
					Period:     period,
					UsedBytes:  physical,
					LimitBytes: physical + max(0, min(personalLeft, left)),
					ExpiresAt:  exitDeadline,
				},
			)
		}
	}
	return out, nil
}

// PreflightBatches checks all pending periods before any can be acknowledged.
func (r *QuotaRepo) PreflightBatches(ctx context.Context, batches []runtimestate.TrafficBatch) error {
	ids := make([]string, 0)
	seen := map[string]bool{}
	for _, batch := range batches {
		for _, sample := range batch.Samples {
			id := sample.ExitID
			if id != "" && id != "direct" && id != "block" && !seen[id] {
				ids = append(ids, id)
				seen[id] = true
			}
		}
	}
	if len(ids) == 0 {
		return nil
	}
	var unknown bool
	err := r.db.Pool.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM quota_exit_membership WHERE scope='vultr') AND
 EXISTS(SELECT 1 FROM unnest($1::text[]) AS pending(exit_id)
 WHERE NOT EXISTS(SELECT 1 FROM quota_exit_membership m WHERE m.exit_id=pending.exit_id))`, ids).Scan(&unknown)
	if err != nil {
		return err
	}
	if unknown {
		return errors.New("unclassified pending quota route")
	}
	return nil
}
