package stats

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
	"github.com/google/uuid"
	xraystats "github.com/xtls/xray-core/features/stats"
)

type measuredStub struct {
	next   map[string]map[string][2]int64
	drains int
}

func (m *measuredStub) GetStatsManager() xraystats.Manager { return nil }
func (m *measuredStub) DrainAccountTraffic() map[string]map[string][2]int64 {
	m.drains++
	out := m.next
	m.next = nil
	return out
}

type userStub []auth.User

func (u userStub) List() []auth.User { return u }

type batchStub struct {
	fail     bool
	received map[string]runtimestate.TrafficBatch
	calls    int
}

func (b *batchStub) RecordSamples(context.Context, []db.TrafficSample) error       { return nil }
func (b *batchStub) PruneOldSamples(context.Context, time.Duration) (int64, error) { return 0, nil }
func (b *batchStub) RecordBatch(_ context.Context, v runtimestate.TrafficBatch) error {
	b.calls++
	if b.received == nil {
		b.received = map[string]runtimestate.TrafficBatch{}
	}
	b.received[v.BatchID] = v
	if b.fail {
		return errors.New("commit response lost")
	}
	return nil
}
func TestDurableReplayKeepsBatchOnAmbiguousCommit(t *testing.T) {
	state, e := runtimestate.Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = state.Close() }()
	owner := uuid.NewString()
	meter := &measuredStub{next: map[string]map[string][2]int64{owner: {"to-exit-exit": {100, 200}}}}
	database := &batchStub{fail: true}
	c := NewDurable(meter, database, userStub{}, state, nil)
	ctx := context.Background()
	if e = c.Checkpoint(ctx); e != nil {
		t.Fatal(e)
	}
	if e = c.Replay(ctx); e == nil {
		t.Fatal("failed commit acknowledged")
	}
	count, _, _, _ := state.PendingStats()
	if count != 1 {
		t.Fatalf("lost batch %d", count)
	}
	database.fail = false
	if e = c.Replay(ctx); e != nil {
		t.Fatal(e)
	}
	if database.calls != 2 || len(database.received) != 1 {
		t.Fatal("retry changed batch identity")
	}
	count, _, _, _ = state.PendingStats()
	if count != 0 {
		t.Fatal("ack did not remove batch")
	}
	for _, b := range database.received {
		if len(b.Samples) != 1 || b.Samples[0].AccountID != owner || b.Samples[0].UplinkBytes != 100 {
			t.Fatalf("wrong attribution %#v", b)
		}
	}
}
func TestCheckpointWithoutDatabase(t *testing.T) {
	state, e := runtimestate.Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = state.Close() }()
	meter := &measuredStub{next: map[string]map[string][2]int64{uuid.NewString(): {"to-exit-exit": {1, 2}}}}
	c := NewDurable(meter, nil, userStub{}, state, nil)
	if c.interval != 5*time.Second {
		t.Fatalf("interval %v", c.interval)
	}
	if e = c.Checkpoint(context.Background()); e != nil {
		t.Fatal(e)
	}
	count, _, _, _ := state.PendingStats()
	if count != 1 {
		t.Fatal("offline traffic not journaled")
	}
}

func TestRetryRetainsFullReconciliationMode(t *testing.T) {
	state, e := runtimestate.Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = state.Close() }()
	now := time.Now().UTC()
	owner := uuid.NewString()
	period := now.Format("2006-01")
	limits := []runtimestate.QuotaLimit{
		{AccountID: owner, ExitID: "exit", Period: period, LimitBytes: 1 << 20, ExpiresAt: now.Add(time.Hour)},
		{ExitID: "exit", Period: period, LimitBytes: 1 << 20, ExpiresAt: now.Add(time.Hour)},
	}
	if e = state.SaveSnapshot(runtimestate.Snapshot{ConfirmedAt: now, Payload: []byte(`{}`)}, limits); e != nil {
		t.Fatal(e)
	}
	if _, e = state.Reserve(owner, "exit", 1); e != nil {
		t.Fatal(e)
	}
	c := NewDurable(&measuredStub{}, &batchStub{}, userStub{}, state, nil)
	ctx := context.Background()
	if e = c.Checkpoint(ctx); e != nil {
		t.Fatal(e)
	}
	if e = c.Replay(ctx); e != nil {
		t.Fatal(e)
	}
	// Disk failure retains the requested reconciliation mode along with the drained identity.
	pending := runtimestate.TrafficBatch{NodeID: state.NodeID(), BatchID: uuid.NewString(), CollectedAt: now}
	c.pending = &pending
	c.pendingFull = true
	if e = c.Checkpoint(ctx); e != nil {
		t.Fatal(e)
	}
	batches, e := state.PendingBatches(10)
	if e != nil || len(batches) != 1 || batches[0].BatchID != pending.BatchID ||
		batches[0].Samples[0].ChargeTotalBytes != runtimestate.ReservationChunk {
		t.Fatalf("full retry lost %v %v", batches, e)
	}
	if c.pending != nil || c.pendingFull {
		t.Fatal("acknowledged memory batch retained")
	}
}
