package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	boltErrors "go.etcd.io/bbolt/errors"

	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
)

type drainReceiver struct {
	fail    bool
	batches []runtimestate.TrafficBatch
}

func (r *drainReceiver) RecordBatch(_ context.Context, b runtimestate.TrafficBatch) error {
	r.batches = append(r.batches, b)
	if r.fail {
		return errors.New("commit acknowledgement lost")
	}
	return nil
}

func TestDrainJournalPreservesUnacknowledgedBatchAndCrashReservations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	state, err := runtimestate.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = state.Close() }()
	now := time.Now().UTC()
	limits := []runtimestate.QuotaLimit{}
	for _, account := range []string{"owner", ""} {
		limits = append(
			limits,
			runtimestate.QuotaLimit{
				AccountID:  account,
				ExitID:     "exit",
				Period:     now.Format("2006-01"),
				LimitBytes: 1 << 20,
				ExpiresAt:  now.Add(time.Hour),
			},
		)
	}
	if err := state.SaveSnapshot(runtimestate.Snapshot{Revision: 1, ConfirmedAt: now, Payload: []byte(`{}`)}, limits); err != nil {
		t.Fatal(err)
	}
	if _, err := state.Reserve("owner", "exit", 1); err != nil {
		t.Fatal(err)
	}
	if err := state.AppendBatch(runtimestate.TrafficBatch{NodeID: state.NodeID(), BatchID: "retained", CollectedAt: now}); err != nil {
		t.Fatal(err)
	}
	receiver := &drainReceiver{fail: true}
	if err := drainJournalStore(context.Background(), state, receiver); err == nil {
		t.Fatal("unconfirmed commit accepted")
	}
	count, _, _, err := state.PendingStats()
	if err != nil || count != 1 {
		t.Fatal("unconfirmed batch removed", count, err)
	}
	receiver.fail = false
	if err := drainJournalStore(context.Background(), state, receiver); err != nil {
		t.Fatal(err)
	}
	count, _, _, err = state.PendingStats()
	if err != nil || count != 0 {
		t.Fatal("drain incomplete", count, err)
	}
	if len(receiver.batches) != 3 || receiver.batches[0].BatchID != receiver.batches[1].BatchID {
		t.Fatal("retry changed identity")
	}
	for _, b := range receiver.batches {
		if len(b.Samples) != 1 || b.Samples[0].ChargeTotalBytes != runtimestate.ReservationChunk {
			t.Fatal("crash reservation lost")
		}
	}
}

func TestDrainJournalRefusesMissingEmptyAndNonregularState(t *testing.T) {
	spec := &config.Spec{Database: &config.DatabaseSpec{DSN: "postgres://test:test@127.0.0.1:1/test?sslmode=disable"}}
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.db")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias.db")
	if err := os.Symlink(empty, alias); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(dir, "missing.db"), empty, alias, dir} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := drainJournal(ctx, spec, path)
		cancel()
		if err == nil {
			t.Fatalf("drained unusable state %s", path)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "missing.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("drain created missing state")
	}
	info, err := os.Stat(empty)
	if err != nil || info.Size() != 0 {
		t.Fatal("drain initialized truncated state")
	}
}
func TestDrainJournalCannotAcquireActiveRelayStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	state, err := runtimestate.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = state.Close() }()
	spec := &config.Spec{Database: &config.DatabaseSpec{DSN: "postgres://test:test@127.0.0.1:1/test?sslmode=disable"}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err = drainJournal(ctx, spec, path); !errors.Is(err, boltErrors.ErrTimeout) {
		t.Fatalf("active journal drain not stopped by file lock: %v", err)
	}
	if state.NodeID() == "" {
		t.Fatal("active store changed")
	}
}
