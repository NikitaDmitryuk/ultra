package runtimestate

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
	boltErrors "go.etcd.io/bbolt/errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T, capacity int64) (*Store, string, *time.Time, []QuotaLimit) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	q := []QuotaLimit{{AccountID: "account", ExitID: "exit", Period: "2026-10", LimitBytes: capacity, ExpiresAt: now.Add(48 * time.Hour)}, {ExitID: "exit", Period: "2026-10", LimitBytes: capacity, ExpiresAt: now.Add(48 * time.Hour)}}
	if e = s.SaveSnapshot(Snapshot{Revision: 1, ConfirmedAt: now, Payload: []byte(`{}`)}, q); e != nil {
		t.Fatal(e)
	}
	return s, path, &now, q
}
func TestReservationSurvivesCrashAndCannotReset(t *testing.T) {
	s, path, now, q := fixture(t, ReservationChunk*2)
	id := s.NodeID()
	grant, e := s.Reserve("account", "exit", 1)
	if e != nil || grant != 1 {
		t.Fatalf("grant %d %v", grant, e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = s.Close() }()
	s.now = func() time.Time { return *now }
	if s.NodeID() != id {
		t.Fatal("node identity changed")
	}
	if e = s.SaveSnapshot(Snapshot{ConfirmedAt: *now, Payload: []byte(`{}`)}, q); e != nil {
		t.Fatal(e)
	}
	left, e := s.Remaining("account", "exit")
	if e != nil || left != ReservationChunk {
		t.Fatalf("lost reserve refunded %d %v", left, e)
	}
	batch := TrafficBatch{BatchID: uuid.NewString(), NodeID: id, CollectedAt: *now}
	if e = s.AppendBatch(batch); e != nil {
		t.Fatal(e)
	}
	b, e := s.PendingBatches(1)
	if e != nil || len(b) != 1 || b[0].Samples[0].ChargeTotalBytes != ReservationChunk {
		t.Fatalf("crash charges missing %#v %v", b, e)
	}
}
func TestReservationSharedAcrossConcurrentConnections(t *testing.T) {
	s, _, _, _ := fixture(t, ReservationChunk)
	defer func() { _ = s.Close() }()
	var wg sync.WaitGroup
	var mu sync.Mutex
	var total int64
	for range 8 {
		wg.Go(func() {
			for range 100 {
				n, e := s.Reserve("account", "exit", 1024)
				if e != nil && !errors.Is(e, ErrQuota) {
					t.Error(e)
				}
				mu.Lock()
				total += n
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if total != ReservationChunk {
		t.Fatalf("shared quota overspend %d", total)
	}
}
func TestSnapshotDeadlineDoesNotRenewOnRestartOrLimits(t *testing.T) {
	s, _, now, q := fixture(t, 1_000_000)
	defer func() { _ = s.Close() }()
	*now = now.Add(SnapshotTTL)
	if e := s.SetQuotaLimits(q); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Reserve("account", "exit", 1); !errors.Is(e, ErrExpired) {
		t.Fatalf("stale snapshot accepted %v", e)
	}
}
func TestEmergencyAllowanceCannotReset(t *testing.T) {
	s, path, now, q := fixture(t, ReservationChunk*10)
	q[1].EmergencyAfter = *now
	q[1].EmergencyBytes = 1024
	if e := s.SetQuotaLimits(q); e != nil {
		t.Fatal(e)
	}
	if n, e := s.Reserve("account", "exit", 512); e != nil || n != 512 {
		t.Fatalf("first %d %v", n, e)
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = s.Close() }()
	s.now = func() time.Time { return *now }
	if e = s.SetQuotaLimits(q); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Reserve("account", "exit", 1); !errors.Is(e, ErrQuota) {
		t.Fatalf("emergency reservation refunded %v", e)
	}
}
func TestRollbackRetainsSpendAndOriginalDeadline(t *testing.T) {
	s, _, now, q := fixture(t, ReservationChunk*2)
	defer func() { _ = s.Close() }()
	old, e := s.LoadSnapshot()
	if e != nil {
		t.Fatal(e)
	}
	*now = now.Add(time.Hour)
	if e = s.SaveSnapshot(Snapshot{ConfirmedAt: *now, Payload: []byte(`{"candidate":true}`)}, q); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Reserve("account", "exit", 10); e != nil {
		t.Fatal(e)
	}
	if e = s.RestoreSnapshot(&old, q); e != nil {
		t.Fatal(e)
	}
	snapshot, _ := s.LoadSnapshot()
	if !snapshot.ConfirmedAt.Equal(old.ConfirmedAt) {
		t.Fatal("rollback extended lease")
	}
	left, _ := s.Remaining("account", "exit")
	if left != 2*ReservationChunk-10 {
		t.Fatalf("rollback spend lost %d", left)
	}
}

func TestFailedObservationCandidateDoesNotRenewEmergencyAllowance(t *testing.T) {
	s, path, now, limits := fixture(t, ReservationChunk*10)
	defer func() { _ = s.Close() }()
	limits[1].EmergencyAfter = *now
	limits[1].EmergencyBytes = ReservationChunk
	if err := s.SetQuotaLimits(limits); err != nil {
		t.Fatal(err)
	}
	old, err := s.LoadSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if n, err := s.Reserve("account", "exit", ReservationChunk); err != nil || n != ReservationChunk {
		t.Fatalf("original emergency allowance: %d %v", n, err)
	}
	candidate := append([]QuotaLimit(nil), limits...)
	candidate[1].EmergencyAfter = now.Add(time.Hour)
	if err := s.SaveSnapshot(Snapshot{ConfirmedAt: *now, Payload: []byte(`{"candidate":true}`)}, candidate); err != nil {
		t.Fatal(err)
	}
	// A crash can happen between saving the candidate and rolling back its failed apply.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return *now }
	if err := s.RestoreSnapshot(&old, limits); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Reserve("account", "exit", 1); !errors.Is(err, ErrQuota) || n != 0 {
		t.Fatalf("rollback renewed exhausted provider episode: %d %v", n, err)
	}
	// A genuinely new confirmed observation starts a distinct emergency episode.
	if err := s.SetQuotaLimits(candidate); err != nil {
		t.Fatal(err)
	}
	*now = candidate[1].EmergencyAfter
	if n, err := s.Reserve("account", "exit", ReservationChunk); err != nil || n != ReservationChunk {
		t.Fatalf("new observation did not obtain its own episode: %d %v", n, err)
	}
}
func TestJournalFullStopsNewReservations(t *testing.T) {
	s, _, _, _ := fixture(t, ReservationChunk)
	defer func() { _ = s.Close() }()
	if e := s.db.Update(func(tx *bolt.Tx) error { return putJournalBytes(tx, MaxPendingBytes) }); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Reserve("account", "exit", 1); !errors.Is(e, ErrJournalFull) {
		t.Fatalf("full journal permits transfer %v", e)
	}
}

func TestPrepaidBuffersDoNotCommitAgain(t *testing.T) {
	s, _, _, q := fixture(t, ReservationChunk*2)
	defer func() { _ = s.Close() }()
	if _, e := s.Reserve("account", "exit", 1); e != nil {
		t.Fatal(e)
	}
	beforeStats := s.db.Stats()
	before := beforeStats.TxStats.GetWrite()
	for range 100 {
		if n, e := s.Reserve("account", "exit", 1024); e != nil || n != 1024 {
			t.Fatalf("grant %d %v", n, e)
		}
	}
	afterStats := s.db.Stats()
	after := afterStats.TxStats.GetWrite()
	if before != after {
		t.Fatalf("prepaid buffer wrote disk: %d -> %d", before, after)
	}
	q[0].ExpiresAt = time.Now().Add(-48 * time.Hour)
	if e := s.SetQuotaLimits(q); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Reserve("account", "exit", 1); !errors.Is(e, ErrExpired) {
		t.Fatalf("prepaid credit bypassed revoked lease: %v", e)
	}
}

func TestJournalCounterAppendDuplicateAckAndReopen(t *testing.T) {
	s, path, now, _ := fixture(t, ReservationChunk)
	batch := TrafficBatch{Version: 1, NodeID: s.NodeID(), BatchID: uuid.NewString(), CollectedAt: *now, Samples: []Sample{{AccountID: "account", ExitID: "exit", UplinkBytes: 1}}}
	if e := s.AppendBatch(batch); e != nil {
		t.Fatal(e)
	}
	read := func() int64 {
		var n int64
		if e := s.db.View(func(tx *bolt.Tx) error { n = journalBytes(tx); return nil }); e != nil {
			t.Fatal(e)
		}
		return n
	}
	before := read()
	if before == 0 {
		t.Fatal("journal not counted")
	}
	if e := s.AppendBatch(batch); e != nil {
		t.Fatal(e)
	}
	if read() != before {
		t.Fatal("duplicate inflated counter")
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	var e error
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = s.Close() }()
	if read() != before {
		t.Fatal("counter lost on reopen")
	}
	if e = s.AckBatch(batch.BatchID); e != nil {
		t.Fatal(e)
	}
	if read() != 0 {
		t.Fatal("ack did not subtract size")
	}
	if e = s.AckBatch(batch.BatchID); e != nil {
		t.Fatal(e)
	}
	if read() != 0 {
		t.Fatal("duplicate ack underflowed size")
	}
	if e = s.db.Update(func(tx *bolt.Tx) error { return putJournalBytes(tx, MaxPendingBytes) }); e != nil {
		t.Fatal(e)
	}
	batch.BatchID = uuid.NewString()
	if e = s.AppendBatch(batch); !errors.Is(e, ErrJournalFull) {
		t.Fatal(e)
	}
	if read() != MaxPendingBytes {
		t.Fatal("failed append changed counter")
	}
}

func TestTruncatedExistingJournalCannotForgiveReservedTraffic(t *testing.T) {
	s, path, _, _ := fixture(t, ReservationChunk*2)
	if _, e := s.Reserve("account", "exit", 1); e != nil {
		t.Fatal(e)
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	if e := os.Truncate(path, 0); e != nil {
		t.Fatal(e)
	}
	reopened, e := Open(path)
	if e == nil {
		_ = reopened.Close()
		t.Fatal("truncated accounting journal was recreated")
	}
	info, e := os.Stat(path)
	if e != nil || info.Size() != 0 {
		t.Fatalf("failed open rewrote corrupt journal %v", e)
	}
}
func TestJournalRejectsSymlinkAndDirectoryBeforeOpening(t *testing.T) {
	s, path, _, _ := fixture(t, ReservationChunk)
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	alias := filepath.Join(t.TempDir(), "alias.db")
	if e := os.Symlink(path, alias); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{alias, t.TempDir()} {
		store, e := Open(name)
		if e == nil {
			_ = store.Close()
			t.Fatalf("accepted nonregular state %s", name)
		}
	}
	reopened, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	_ = reopened.Close()
}

func TestReadOnlyDatabaseRejectsNewReservationsAndRetainsQueue(t *testing.T) {
	s, path, now, _ := fixture(t, ReservationChunk*2)
	node := s.NodeID()
	if _, e := s.Reserve("account", "exit", 1); e != nil {
		t.Fatal(e)
	}
	id := uuid.NewString()
	if e := s.AppendBatch(TrafficBatch{NodeID: node, BatchID: id, CollectedAt: *now}); e != nil {
		t.Fatal(e)
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	readonly, e := bolt.Open(path, 0600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	s.db = readonly
	// Remaining prepaid credit is smaller than this request: a new synced reserve
	// would be required and must fail before any bytes are permitted.
	if grant, e := s.Reserve("account", "exit", ReservationChunk); !errors.Is(e, boltErrors.ErrDatabaseReadOnly) || grant != 0 {
		_ = readonly.Close()
		t.Fatalf("read-only state permitted new reserve: %d %v", grant, e)
	}
	pending, e := s.PendingBatches(10)
	if e != nil || len(pending) != 1 || pending[0].BatchID != id {
		_ = readonly.Close()
		t.Fatalf("read-only failure lost pending traffic: %v %v", pending, e)
	}
	if e = readonly.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = reopened.Close() }()
	reopened.now = func() time.Time { return *now }
	left, e := reopened.Remaining("account", "exit")
	if e != nil || left != ReservationChunk || reopened.NodeID() != node {
		t.Fatalf("read-only error refunded durable charges: %d %v", left, e)
	}
	pending, e = reopened.PendingBatches(10)
	if e != nil || len(pending) != 1 || pending[0].BatchID != id {
		t.Fatal("reopening lost committed journal")
	}
}

func TestDirtyCheckpointIdleHistoricalRestartAndRetryIdentity(t *testing.T) {
	s, path, now, _ := fixture(t, ReservationChunk*4)
	// Historical states remain as conservative accounting evidence after expiry.
	if err := s.db.Update(func(tx *bolt.Tx) error {
		for i := 1; i <= 24; i++ {
			q := quotaState{QuotaLimit: QuotaLimit{AccountID: "historical", ExitID: "exit", Period: fmt.Sprintf("2024-%02d", i), ExpiresAt: now.Add(-time.Hour)}, Spent: int64(i)}
			raw, _ := json.Marshal(q)
			if err := tx.Bucket(quotaBucket).Put([]byte(quotaKey(q.AccountID, q.ExitID, q.Period)), raw); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reserve("account", "exit", 1); err != nil {
		t.Fatal(err)
	}
	batch := TrafficBatch{NodeID: s.NodeID(), BatchID: uuid.NewString(), CollectedAt: *now}
	if err := s.AppendBatch(batch); err != nil {
		t.Fatal(err)
	}
	initial, err := s.PendingBatches(10)
	if err != nil || len(initial) != 1 || len(initial[0].Samples) != 25 {
		t.Fatalf("initial historical charges: %v %v", initial, err)
	}
	// Reusing an identity must preserve the exact enriched payload even after spend advances.
	if _, err = s.Reserve("account", "exit", ReservationChunk); err != nil {
		t.Fatal(err)
	}
	if err = s.AppendBatch(batch); err != nil {
		t.Fatal(err)
	}
	retried, _ := s.PendingBatches(10)
	if !reflect.DeepEqual(initial, retried) {
		t.Fatal("retry changed durable batch")
	}
	if err = s.AckBatch(batch.BatchID); err != nil {
		t.Fatal(err)
	}
	next := func(full bool) {
		t.Helper()
		b := TrafficBatch{NodeID: s.NodeID(), BatchID: uuid.NewString(), CollectedAt: *now}
		var e error
		if full {
			e = s.AppendBatchFull(b)
		} else {
			e = s.AppendBatch(b)
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	next(false)
	pending, _ := s.PendingBatches(10)
	if len(pending) != 1 || len(pending[0].Samples) != 1 || pending[0].Samples[0].ChargeTotalBytes != ReservationChunk+1 {
		t.Fatalf("dirty charge %v", pending)
	}
	if err = s.AckBatch(pending[0].BatchID); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	s.now = func() time.Time { return *now }
	for range 100 {
		next(false)
	}
	count, size, _, err := s.PendingStats()
	if err != nil || count != 0 || size != 0 {
		t.Fatalf("idle journal grew %d %d %v", count, size, err)
	}
	next(true)
	pending, _ = s.PendingBatches(10)
	if len(pending) != 1 || len(pending[0].Samples) != 25 {
		t.Fatalf("forced reconciliation omitted history %v", pending)
	}
}

func TestDirtyWatermarkNotAdvancedWhenJournalWriteFails(t *testing.T) {
	s, _, now, _ := fixture(t, ReservationChunk)
	defer func() { _ = s.Close() }()
	if _, err := s.Reserve("account", "exit", 1); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Update(func(tx *bolt.Tx) error { return putJournalBytes(tx, MaxPendingBytes) }); err != nil {
		t.Fatal(err)
	}
	batch := TrafficBatch{NodeID: s.NodeID(), BatchID: uuid.NewString(), CollectedAt: *now}
	if err := s.AppendBatch(batch); !errors.Is(err, ErrJournalFull) {
		t.Fatalf("write failure %v", err)
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(chargeWatermarkBucket).Get([]byte(quotaKey("account", "exit", "2026-10"))) != nil {
			t.Fatal("failed append advanced watermark")
		}
		return putJournalBytes(tx, 0)
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendBatch(batch); err != nil {
		t.Fatal(err)
	}
	pending, _ := s.PendingBatches(1)
	if len(pending) != 1 || pending[0].Samples[0].ChargeTotalBytes != ReservationChunk {
		t.Fatal("retry lost crash charge")
	}
}

func TestCompatibleOlderAcknowledgementPreservesWatermarksAndReclaimsDigests(t *testing.T) {
	s, path, now, _ := fixture(t, ReservationChunk)
	if _, err := s.Reserve("account", "exit", 1); err != nil {
		t.Fatal(err)
	}
	batch := TrafficBatch{NodeID: s.NodeID(), BatchID: uuid.NewString(), CollectedAt: *now}
	if err := s.AppendBatch(batch); err != nil {
		t.Fatal(err)
	}
	// Old accounting-aware binaries preserve unknown buckets but only delete their journal row.
	if err := s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(batchBucket).Delete([]byte(batch.BatchID)) }); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	s.now = func() time.Time { return *now }
	if err = s.db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(batchInputBucket).Stats().KeyN != 0 {
			t.Fatal("orphaned input digest retained")
		}
		if tx.Bucket(chargeWatermarkBucket).Stats().KeyN != 1 {
			t.Fatal("compatible rollback lost watermark")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	batch.BatchID = uuid.NewString()
	if err = s.AppendBatch(batch); err != nil {
		t.Fatal(err)
	}
	pending, err := s.PendingBatches(10)
	if err != nil || len(pending) != 0 {
		t.Fatalf("old ACK caused idle duplicate %v %v", pending, err)
	}
	left, err := s.Remaining("account", "exit")
	if err != nil || left != 0 {
		t.Fatalf("old ACK returned budget %d %v", left, err)
	}
}
