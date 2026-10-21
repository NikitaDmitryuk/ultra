package db

import (
	"context"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
	"github.com/google/uuid"
)

func TestProviderPoolSurvivesReplacementRotationDeletionAndLateBatch(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	r := NewQuotaRepo(d)
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	old, replacement, manual, user := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	for i, id := range []string{old, replacement, manual} {
		if _, err := d.Pool.Exec(ctx, `INSERT INTO exit_nodes(id,name,address,port,tunnel_uuid) VALUES($1::uuid,'fixture','192.0.2.1',$2,$1::text)`, id, 440+i); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.Pool.Exec(ctx, `INSERT INTO users(uuid,name,telegram_id,enrollment_source) VALUES($1,'fixture',123,'invite')`, user); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{old, replacement} {
		if err := r.EnsureVultr(ctx, id, id, 900000); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.Pool.Exec(ctx, `INSERT INTO exit_traffic_budgets(exit_id,monthly_bytes,source,is_fallback) VALUES($1,10000,'manual',true)`, manual); err != nil {
		t.Fatal(err)
	}
	if err := r.SaveBandwidth(ctx, []BandwidthObservation{{ID: old, Instance: old, Monthly: 900000, Remaining: 800, Accrued: 1000, Pool: true}, {ID: replacement, Instance: replacement, Monthly: 900000, Remaining: 800, Accrued: 1000, Pool: true}}, now); err != nil {
		t.Fatal(err)
	}
	var owner string
	if err := d.Pool.QueryRow(ctx, `SELECT account_id::text FROM users WHERE uuid=$1`, user).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	batch := runtimestate.TrafficBatch{
		Version:     1,
		NodeID:      uuid.NewString(),
		BatchID:     uuid.NewString(),
		CollectedAt: now,
		Samples:     []runtimestate.Sample{{AccountID: owner, ExitID: old, ExitTag: "to-exit-" + old, ChargeTotalBytes: 150}},
	}
	traffic := NewTrafficRepo(d)
	for range 2 {
		if err := traffic.RecordBatch(ctx, batch); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.Pool.Exec(ctx, `DELETE FROM exit_nodes WHERE id=$1`, old); err != nil {
		t.Fatal(err)
	}
	rotated, err := NewUserRepo(d).RotateUUID(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Recalculate(ctx, now); err != nil {
		t.Fatal(err)
	}
	q, err := r.SubscriptionQuota(ctx, owner, now)
	if err != nil || q.PersonalLimit != 200 || q.Used != 150 || q.Remaining != 50 {
		t.Fatal("replacement/rotation changed quota", q, err)
	}
	batch.BatchID = uuid.NewString()
	batch.Samples[0].ExitID = replacement
	batch.Samples[0].ChargeTotalBytes = 50
	if err = traffic.RecordBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Recalculate(ctx, now); err != nil {
		t.Fatal(err)
	}
	var blocked bool
	if err = d.Pool.QueryRow(ctx, `SELECT blocked FROM user_exit_quotas WHERE user_uuid=$1 AND exit_id=$2`, rotated, replacement).Scan(&blocked); err != nil ||
		!blocked {
		t.Fatal("aggregate personal quota not enforced", blocked, err)
	}
	if err = d.Pool.QueryRow(ctx, `SELECT blocked FROM user_exit_quotas WHERE user_uuid=$1 AND exit_id=$2`, rotated, manual).Scan(&blocked); err != nil ||
		blocked {
		t.Fatal("manual fallback blocked", blocked, err)
	}
	if _, err = d.Pool.Exec(ctx, `DELETE FROM users WHERE uuid=$1`, rotated); err != nil {
		t.Fatal(err)
	}
	batch.BatchID = uuid.NewString()
	batch.Samples[0].ChargeTotalBytes = 100
	if err = traffic.RecordBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	used, err := r.ProviderWatermark(ctx, now)
	if err != nil || used != 250 {
		t.Fatal("deleted owner cost lost", used, err)
	}
	var count int
	if err = d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE account_id=$1`, owner).Scan(&count); err != nil || count != 0 {
		t.Fatal("late traffic restored user", count, err)
	}
}

func TestPoolRejectsUnclassifiedExpenseAndMonthWithoutObservation(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	r := NewQuotaRepo(d)
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	exit, owner := uuid.NewString(), uuid.NewString()
	if _, err := d.Pool.Exec(ctx, `INSERT INTO exit_nodes(id,name,address,port,tunnel_uuid) VALUES($1::uuid,'fixture','192.0.2.1',443,$1::text);`, exit); err != nil {
		t.Fatal(err)
	}
	if err := r.EnsureVultr(ctx, exit, exit, 999999); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Pool.Exec(ctx, `INSERT INTO traffic_accounts(account_id) VALUES($1)`, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Pool.Exec(ctx, `INSERT INTO account_exit_usage(account_id,exit_id,period,charged_bytes) VALUES($1,'unknown-removed','2026-10',1)`, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Recalculate(ctx, now); err == nil {
		t.Fatal("unclassified expense silently excluded")
	}
	if _, err := d.Pool.Exec(ctx, `INSERT INTO quota_exit_membership VALUES('unknown-removed','vultr')`); err != nil {
		t.Fatal(err)
	}
	if err := r.SaveBandwidth(ctx, []BandwidthObservation{{ID: exit, Instance: exit, Monthly: 999999, Remaining: 800, Accrued: 1000, Pool: true}}, now); err != nil {
		t.Fatal(err)
	}
	q, err := r.SubscriptionQuota(ctx, owner, now.AddDate(0, 1, 0))
	if err != nil || q.Remaining != 0 || q.PersonalLimit != 0 || q.State != "unknown" {
		t.Fatal("month fabricated new credits", q, err)
	}
}

func TestPoolPendingOldPeriodCannotBypassBackgroundReplay(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	r := NewQuotaRepo(d)
	exit := uuid.NewString()
	if _, err := d.Pool.Exec(ctx, `INSERT INTO exit_nodes(id,name,address,port,tunnel_uuid) VALUES($1::uuid,'fixture','192.0.2.1',443,$1::text)`, exit); err != nil {
		t.Fatal(err)
	}
	if err := r.EnsureVultr(ctx, exit, exit, 1000); err != nil {
		t.Fatal(err)
	}
	batch := runtimestate.TrafficBatch{
		Version:     1,
		NodeID:      uuid.NewString(),
		BatchID:     uuid.NewString(),
		CollectedAt: time.Now(),
		Samples: []runtimestate.Sample{
			{AccountID: uuid.NewString(), ExitID: "unknown-pending", Period: "2026-09", ChargeTotalBytes: 50},
		},
	}
	if err := NewTrafficRepo(d).RecordBatch(ctx, batch); err == nil {
		t.Fatal("background replay accepted unclassified old-period spend")
	}
	var recorded bool
	if err := d.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM traffic_batches WHERE batch_id=$1)`, batch.BatchID).Scan(&recorded); err != nil ||
		recorded {
		t.Fatal("unsafe batch acknowledged", recorded, err)
	}
}

func TestPoolPartialSchemaFailsClosed(t *testing.T) {
	for _, ddl := range []string{`ALTER TABLE exit_traffic_budgets DISABLE TRIGGER quota_exit_membership`, `ALTER TABLE provider_quota_pools DROP COLUMN observed_local_bytes`} {
		t.Run(ddl, func(t *testing.T) {
			d := openTestDB(t)
			ctx := context.Background()
			if _, err := d.Pool.Exec(ctx, ddl); err != nil {
				t.Fatal(err)
			}
			if err := d.migrate(ctx); err == nil {
				t.Fatal("partial pool schema accepted")
			}
		})
	}
}
