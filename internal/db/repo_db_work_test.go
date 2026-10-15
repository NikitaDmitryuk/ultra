package db

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/db/sqlc"
	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Count server statements, including pipelined statements, rather than inferring
// savings from timings on a developer machine.
type statementCounter struct{ count atomic.Int64 }

func (c *statementCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	c.count.Add(1)
	return ctx
}
func (*statementCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func (*statementCounter) TraceBatchStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceBatchStartData) context.Context {
	return ctx
}
func (c *statementCounter) TraceBatchQuery(context.Context, *pgx.Conn, pgx.TraceBatchQueryData) {
	c.count.Add(1)
}
func (*statementCounter) TraceBatchEnd(context.Context, *pgx.Conn, pgx.TraceBatchEndData) {}
func countedDB(t *testing.T, d *DB) (*DB, *statementCounter) {
	t.Helper()
	cfg := d.Pool.Config()
	counter := &statementCounter{}
	cfg.ConnConfig.Tracer = counter
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	orm, adapter, err := newORM(pool)
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	shared := &DB{Pool: pool, Queries: sqlc.New(pool), orm: orm, ormSQL: adapter}
	t.Cleanup(shared.Close)
	return shared, counter
}

func TestBatchSetWritesPreserveDestinationsAndBoundStatements(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	at := time.Date(2026, 2, 1, 1, 2, 3, 0, time.FixedZone("east", 3*3600))
	user := uuid.NewString()
	if _, err := d.Pool.Exec(ctx, `INSERT INTO users(uuid,name) VALUES($1,'batch-work')`, user); err != nil {
		t.Fatal(err)
	}
	u, _, err := NewUserRepo(d).Lookup(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	counted, counter := countedDB(t, d)
	repo := NewTrafficRepo(counted)
	batch := runtimestate.TrafficBatch{Version: 1, NodeID: uuid.NewString(), BatchID: uuid.NewString(), CollectedAt: at}
	for i := range 30 {
		batch.Samples = append(
			batch.Samples,
			runtimestate.Sample{
				AccountID:        u.AccountID,
				ExitID:           "exit",
				ExitTag:          "to-exit-exit",
				UplinkBytes:      1,
				DownlinkBytes:    2,
				ChargeTotalBytes: int64(100 + i),
			},
		)
	}
	batch.Samples = append(
		batch.Samples,
		runtimestate.Sample{
			AccountID:        u.AccountID,
			ExitID:           "direct",
			ExitTag:          "direct",
			UplinkBytes:      7,
			Period:           "2025-12",
			ChargeTotalBytes: 70,
		},
	)
	if err := repo.RecordBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if got := counter.count.Load(); got != 10 {
		t.Fatalf("31 samples used %d statements; want 10", got)
	}
	var up, down, charge int64
	if err := d.Pool.QueryRow(ctx, `SELECT uplink_bytes,downlink_bytes,charged_bytes FROM account_exit_usage WHERE account_id=$1 AND exit_id='exit' AND period='2026-01'`, u.AccountID).Scan(&up, &down, &charge); err != nil ||
		up != 30 ||
		down != 60 ||
		charge != 129 {
		t.Fatalf("account %d %d %d: %v", up, down, charge, err)
	}
	var rawRows int
	var last time.Time
	if err := d.Pool.QueryRow(ctx, `SELECT COUNT(*),SUM(uplink_bytes)::bigint,SUM(downlink_bytes)::bigint,MAX(collected_at) FROM traffic_stats WHERE user_uuid=$1`, user).Scan(&rawRows, &up, &down, &last); err != nil ||
		rawRows != 2 ||
		up != 37 ||
		down != 60 ||
		!last.Equal(at) {
		t.Fatalf("raw rows=%d bytes=%d/%d last=%v: %v", rawRows, up, down, last, err)
	}
	if err := d.Pool.QueryRow(ctx, `SELECT uplink_bytes,downlink_bytes FROM monthly_traffic WHERE user_uuid=$1 AND year=2026 AND month=1`, user).Scan(&up, &down); err != nil ||
		up != 37 ||
		down != 60 {
		t.Fatalf("monthly %d/%d: %v", up, down, err)
	}
	if err := d.Pool.QueryRow(ctx, `SELECT SUM(uplink_bytes)::bigint,SUM(downlink_bytes)::bigint FROM daily_route_traffic WHERE user_uuid=$1 AND day='2026-01-31'`, user).Scan(&up, &down); err != nil ||
		up != 37 ||
		down != 60 {
		t.Fatalf("daily %d/%d: %v", up, down, err)
	}
	if err := repo.RecordBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if err := d.Pool.QueryRow(ctx, `SELECT SUM(uplink_bytes)::bigint FROM traffic_stats WHERE user_uuid=$1`, user).Scan(&up); err != nil ||
		up != 37 {
		t.Fatalf("replay %d: %v", up, err)
	}
}

func TestLeakObservationBatchPreservesPollCountsAndWindows(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	user := uuid.NewString()
	if _, err := d.Pool.Exec(ctx, `INSERT INTO users(uuid,name) VALUES($1,'leak-batch')`, user); err != nil {
		t.Fatal(err)
	}
	counted, counter := countedDB(t, d)
	repo := NewTelegramRepo(counted)
	ips := []string{"192.0.2.1", "192.0.2.1", "2001:db8::1"}
	for range 2 {
		if err := repo.UpsertUserIPObservations(ctx, user, ips); err != nil {
			t.Fatal(err)
		}
	}
	if got := counter.count.Load(); got != 2 {
		t.Fatalf("two poll batches: %d statements", got)
	}
	var sessions int64
	if err := d.Pool.QueryRow(ctx, `SELECT sessions_seen FROM user_ip_observations WHERE user_uuid=$1 AND ip='192.0.2.1'`, user).Scan(&sessions); err != nil ||
		sessions != 4 {
		t.Fatalf("sessions=%d: %v", sessions, err)
	}
	if _, err := d.Pool.Exec(ctx, `UPDATE user_ip_observations SET last_seen_at=NOW()-INTERVAL '2 hours' WHERE user_uuid=$1 AND ip='192.0.2.1'`, user); err != nil {
		t.Fatal(err)
	}
	concurrent, unique, err := repo.LeakIPCounts(ctx, user)
	if err != nil || concurrent != 1 || unique != 2 {
		t.Fatalf("windows=%d/%d: %v", concurrent, unique, err)
	}
	if got := counter.count.Load(); got != 3 {
		t.Fatalf("counts added %d statements; want one", got-2)
	}
	if err := repo.UpsertUserIPObservations(ctx, user, []string{"192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	concurrent, unique, err = repo.LeakIPCounts(ctx, user)
	if err != nil || concurrent != 2 || unique != 2 {
		t.Fatalf("refreshed windows=%d/%d: %v", concurrent, unique, err)
	}
}

func TestQuotaWorkIndependentOfUserCountAndIdleRowsUnchanged(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	exit := uuid.NewString()
	user := uuid.NewString()
	now := time.Now().UTC()
	if _, err := d.Pool.Exec(ctx, `INSERT INTO exit_nodes(id,name,address,port,tunnel_uuid) VALUES($1,'work','192.0.2.1',443,$2)`, exit, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Pool.Exec(ctx, `INSERT INTO exit_traffic_budgets(exit_id,monthly_bytes,source,is_fallback) VALUES($1,1000000,'manual',true)`, exit); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Pool.Exec(ctx, `INSERT INTO users(uuid,name) VALUES($1,'work')`, user); err != nil {
		t.Fatal(err)
	}
	counted, counter := countedDB(t, d)
	repo := NewQuotaRepo(counted)
	if _, err := repo.Recalculate(ctx, now); err != nil {
		t.Fatal(err)
	}
	oneUser := counter.count.Swap(0)
	snapshot, err := repo.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Acknowledge(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	var before, after string
	if err := d.Pool.QueryRow(ctx, `SELECT xmin::text FROM user_exit_quotas WHERE user_uuid=$1 AND exit_id=$2`, user, exit).Scan(&before); err != nil {
		t.Fatal(err)
	}
	changed, err := repo.Recalculate(ctx, now)
	if err != nil || changed {
		t.Fatalf("idle calculation changed=%v: %v", changed, err)
	}
	if err := d.Pool.QueryRow(ctx, `SELECT xmin::text FROM user_exit_quotas WHERE user_uuid=$1 AND exit_id=$2`, user, exit).Scan(&after); err != nil ||
		before != after {
		t.Fatalf("idle quota rewritten %s -> %s: %v", before, after, err)
	}
	for range 30 {
		if _, err := d.Pool.Exec(ctx, `INSERT INTO users(uuid,name) VALUES($1,'work')`, uuid.NewString()); err != nil {
			t.Fatal(err)
		}
	}
	counter.count.Store(0)
	if _, err := repo.Recalculate(ctx, now); err != nil {
		t.Fatal(err)
	}
	if got := counter.count.Load(); got != oneUser {
		t.Fatalf("one user %d statements, 31 users %d", oneUser, got)
	}
	t.Logf("one exit quota calculation: %d statements for both 1 and 31 users", oneUser)
}

func TestBatchSetWriteFailureRollsBackIdentityAndTombstone(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	owner := uuid.NewString()
	at := time.Now().UTC()
	b := runtimestate.TrafficBatch{
		Version:     1,
		NodeID:      uuid.NewString(),
		BatchID:     uuid.NewString(),
		CollectedAt: at,
		Samples: []runtimestate.Sample{
			{AccountID: owner, ExitID: "direct", UplinkBytes: 1<<63 - 1},
			{AccountID: owner, ExitID: "direct", UplinkBytes: 1},
		},
	}
	repo := NewTrafficRepo(d)
	if err := repo.RecordBatch(ctx, b); err == nil {
		t.Fatal("overflowing aggregate accepted")
	}
	var identities, owners int
	if err := d.Pool.QueryRow(ctx, `SELECT (SELECT COUNT(*) FROM traffic_batches WHERE node_id=$1 AND batch_id=$2),(SELECT COUNT(*) FROM traffic_accounts WHERE account_id=$3)`, b.NodeID, b.BatchID, owner).Scan(&identities, &owners); err != nil ||
		identities != 0 ||
		owners != 0 {
		t.Fatalf("partial commit identities=%d owners=%d: %v", identities, owners, err)
	}
	b.Samples[0].UplinkBytes = 2
	if err := repo.RecordBatch(ctx, b); err != nil {
		t.Fatalf("failed transaction retained identity: %v", err)
	}
}
