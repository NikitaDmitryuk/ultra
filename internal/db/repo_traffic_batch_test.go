package db

import (
	"context"
	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
	"github.com/google/uuid"
	"path/filepath"
	"testing"
	"time"
)

func TestBatchIdempotencyRotationAndDeletion(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	user := uuid.NewString()
	if _, e := d.Pool.Exec(ctx, `INSERT INTO users(uuid,name) VALUES($1,'batch')`, user); e != nil {
		t.Fatal(e)
	}
	u, ok, e := NewUserRepo(d).Lookup(ctx, user)
	if e != nil || !ok || u.AccountID == "" {
		t.Fatalf("identity %v %v %#v", ok, e, u)
	}
	at := time.Now().UTC()
	b := runtimestate.TrafficBatch{Version: 1, NodeID: uuid.NewString(), BatchID: uuid.NewString(), CollectedAt: at, Samples: []runtimestate.Sample{{AccountID: u.AccountID, ExitID: "exit", ExitTag: "to-exit-exit", Period: at.Format("2006-01"), UplinkBytes: 100, DownlinkBytes: 200, ChargeTotalBytes: 1024}}}
	r := NewTrafficRepo(d)
	for range 2 {
		if e = r.RecordBatch(ctx, b); e != nil {
			t.Fatal(e)
		}
	}
	var up, down, charge int64
	check := func(wantUp, wantDown, wantCharge int64) {
		t.Helper()
		e := d.Pool.QueryRow(ctx, `SELECT uplink_bytes,downlink_bytes,charged_bytes FROM account_exit_usage WHERE account_id=$1 AND exit_id='exit'`, u.AccountID).Scan(&up, &down, &charge)
		if e != nil || up != wantUp || down != wantDown || charge != wantCharge {
			t.Fatalf("usage %d %d %d %v", up, down, charge, e)
		}
	}
	check(100, 200, 1024)
	conflict := b
	conflict.Samples = append([]runtimestate.Sample(nil), b.Samples...)
	conflict.Samples[0].UplinkBytes++
	if e = r.RecordBatch(ctx, conflict); e == nil {
		t.Fatal("same identity with different bytes accepted")
	}
	rotated, e := NewUserRepo(d).RotateUUID(ctx, user)
	if e != nil {
		t.Fatal(e)
	}
	v, _, e := NewUserRepo(d).Lookup(ctx, rotated)
	if e != nil || v.AccountID != u.AccountID {
		t.Fatalf("rotation changed owner %v %#v", e, v)
	}
	b.BatchID = uuid.NewString()
	b.Samples[0].ChargeTotalBytes = 2048
	if e = r.RecordBatch(ctx, b); e != nil {
		t.Fatal(e)
	}
	check(200, 400, 2048)
	if e = NewUserRepo(d).Purge(ctx, rotated); e != nil {
		t.Fatal(e)
	}
	b.BatchID = uuid.NewString()
	b.Samples[0].ChargeTotalBytes = 4096
	if e = r.RecordBatch(ctx, b); e != nil {
		t.Fatal(e)
	}
	check(300, 600, 4096)
	var count int
	if e = d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE account_id=$1`, u.AccountID).Scan(&count); e != nil || count != 0 {
		t.Fatalf("late batch resurrected owner %d %v", count, e)
	}
}
func TestNotificationLeaseGeneration(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	r := NewTelegramRepo(d)
	if e := r.EnqueueNotification(ctx, Notification{TelegramID: 123, Type: "lease", Payload: map[string]any{}}); e != nil {
		t.Fatal(e)
	}
	first, e := r.ClaimNotifications(ctx, 1, time.Minute)
	if e != nil || len(first) != 1 {
		t.Fatalf("claim %v %v", first, e)
	}
	if _, e = d.Pool.Exec(ctx, `UPDATE notifications SET lease_until=NOW()-INTERVAL '1 second' WHERE id=$1`, first[0].ID); e != nil {
		t.Fatal(e)
	}
	second, e := r.ClaimNotifications(ctx, 1, time.Minute)
	if e != nil || len(second) != 1 || second[0].Attempts != 2 {
		t.Fatalf("reclaim %v %v", second, e)
	}
	if e = r.CompleteClaim(ctx, first[0].ID, first[0].Attempts); e == nil {
		t.Fatal("stale worker completed new lease")
	}
	if e = r.RetryClaim(ctx, first[0].ID, first[0].Attempts, time.Now(), "timeout", false); e == nil {
		t.Fatal("stale worker cleared new lease")
	}
	if e = r.CompleteClaim(ctx, second[0].ID, second[0].Attempts); e != nil {
		t.Fatal(e)
	}
	due, e := r.ClaimNotifications(ctx, 10, time.Minute)
	if e != nil || len(due) != 0 {
		t.Fatalf("sent was reclaimed %v %v", due, e)
	}
}

func TestLateBatchAfterOlderBackupCreatesOnlyAccountingTombstone(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	owner := uuid.NewString()
	at := time.Now().UTC()
	b := runtimestate.TrafficBatch{Version: 1, NodeID: uuid.NewString(), BatchID: uuid.NewString(), CollectedAt: at, Samples: []runtimestate.Sample{{AccountID: owner, ExitID: "restored-exit", ExitTag: "to-exit-restored-exit", Period: at.Format("2006-01"), ChargeTotalBytes: 262144}}}
	if e := NewTrafficRepo(d).RecordBatch(ctx, b); e != nil {
		t.Fatal(e)
	}
	var users int
	var charge int64
	if e := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE account_id=$1`, owner).Scan(&users); e != nil || users != 0 {
		t.Fatalf("resurrected owner %d %v", users, e)
	}
	if e := d.Pool.QueryRow(ctx, `SELECT charged_bytes FROM account_exit_usage WHERE account_id=$1`, owner).Scan(&charge); e != nil || charge != 262144 {
		t.Fatalf("lost restored exit cost %d %v", charge, e)
	}
}
func TestMemberNotificationClaimRetryAndTerminal(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	id := uuid.NewString()
	if _, e := d.Pool.Exec(ctx, `INSERT INTO users(uuid,name,telegram_id,enrollment_source) VALUES($1,'member',123456,'invite')`, id); e != nil {
		t.Fatal(e)
	}
	if _, e := d.Pool.Exec(ctx, `INSERT INTO vpn_member_notifications(member_id,admin_id) VALUES(123456,42)`); e != nil {
		t.Fatal(e)
	}
	r := NewTelegramRepo(d)
	first, e := r.ClaimMemberNotifications(ctx)
	if e != nil || len(first) != 1 || first[0].Attempts != 1 {
		t.Fatalf("claim %v %v", first, e)
	}
	if e = r.RetryMemberNotification(ctx, 123456, 42, 1, time.Now().Add(time.Hour), "rate_limit", false); e != nil {
		t.Fatal(e)
	}
	if e = r.CompleteMemberClaim(ctx, 123456, 42, 1); e == nil {
		t.Fatal("completed released claim")
	}
	if _, e = d.Pool.Exec(ctx, `UPDATE vpn_member_notifications SET next_attempt=NOW()-INTERVAL '1 second'`); e != nil {
		t.Fatal(e)
	}
	second, e := r.ClaimMemberNotifications(ctx)
	if e != nil || len(second) != 1 || second[0].Attempts != 2 {
		t.Fatalf("reclaim %v %v", second, e)
	}
	if e = r.RetryMemberNotification(ctx, 123456, 42, 1, time.Now(), "old_failure", false); e == nil {
		t.Fatal("old worker overwrote claim")
	}
	if e = r.RetryMemberNotification(ctx, 123456, 42, 2, time.Now(), "blocked", true); e != nil {
		t.Fatal(e)
	}
	pending, e := r.ClaimMemberNotifications(ctx)
	if e != nil || len(pending) != 0 {
		t.Fatalf("terminal reclaimed %v %v", pending, e)
	}
}

func TestFullCheckpointRestoresOlderDatabaseWithoutIdleLedgerGrowth(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	user := uuid.NewString()
	if _, err := d.Pool.Exec(ctx, `INSERT INTO users(uuid,name) VALUES($1,'restore')`, user); err != nil {
		t.Fatal(err)
	}
	u, _, err := NewUserRepo(d).Lookup(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	state, err := runtimestate.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = state.Close() }()
	now := time.Now().UTC()
	period := now.Format("2006-01")
	limits := []runtimestate.QuotaLimit{{AccountID: u.AccountID, ExitID: "restore-exit", Period: period, LimitBytes: 1 << 20, ExpiresAt: now.Add(time.Hour)}, {ExitID: "restore-exit", Period: period, LimitBytes: 1 << 20, ExpiresAt: now.Add(time.Hour)}}
	if err = state.SaveSnapshot(runtimestate.Snapshot{ConfirmedAt: now, Payload: []byte(`{}`)}, limits); err != nil {
		t.Fatal(err)
	}
	if _, err = state.Reserve(u.AccountID, "restore-exit", 1); err != nil {
		t.Fatal(err)
	}
	repo := NewTrafficRepo(d)
	checkpoint := func(full bool) {
		t.Helper()
		b := runtimestate.TrafficBatch{NodeID: state.NodeID(), BatchID: uuid.NewString(), CollectedAt: now}
		var e error
		if full {
			e = state.AppendBatchFull(b)
		} else {
			e = state.AppendBatch(b)
		}
		if e != nil {
			t.Fatal(e)
		}
		pending, e := state.PendingBatches(100)
		if e != nil {
			t.Fatal(e)
		}
		for _, batch := range pending {
			if e = repo.RecordBatch(ctx, batch); e != nil {
				t.Fatal(e)
			}
			if e = state.AckBatch(batch.BatchID); e != nil {
				t.Fatal(e)
			}
		}
	}
	checkpoint(false)
	var before, after int
	if err = d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM traffic_batches WHERE node_id=$1`, state.NodeID()).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for range 30 {
		checkpoint(false)
	}
	if err = d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM traffic_batches WHERE node_id=$1`, state.NodeID()).Scan(&after); err != nil || before != after {
		t.Fatalf("idle ledger grew %d -> %d: %v", before, after, err)
	}
	// Simulate restoring an older backup. Runbook fences and restarts relay before this reconciliation.
	if _, err = d.Pool.Exec(ctx, `UPDATE account_exit_usage SET charged_bytes=0 WHERE account_id=$1`, u.AccountID); err != nil {
		t.Fatal(err)
	}
	checkpoint(true)
	var charged, up, down int64
	if err = d.Pool.QueryRow(ctx, `SELECT charged_bytes,uplink_bytes,downlink_bytes FROM account_exit_usage WHERE account_id=$1 AND exit_id='restore-exit'`, u.AccountID).Scan(&charged, &up, &down); err != nil || charged != runtimestate.ReservationChunk || up != 0 || down != 0 {
		t.Fatalf("restore %d %d %d %v", charged, up, down, err)
	}
}
