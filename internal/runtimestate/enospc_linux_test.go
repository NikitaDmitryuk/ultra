//go:build linux

package runtimestate

import (
	"errors"
	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
	"os"
	"syscall"
	"testing"
	"time"
)

// Redirect this test's open database descriptor to /dev/full after mapping the
// valid file. bbolt's actual writeAt then receives the kernel ENOSPC error; the
// original file and host filesystem are untouched. Restore it before reopening.
func TestKernelENOSPCPreservesJournalAndPreventsReservation(t *testing.T) {
	state, path, now, _ := fixture(t, ReservationChunk*3)
	if _, err := state.Reserve("account", "exit", 1); err != nil {
		t.Fatal(err)
	}
	batch := TrafficBatch{NodeID: state.NodeID(), BatchID: uuid.NewString(), CollectedAt: *now}
	if err := state.AppendBatch(batch); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	var file *os.File
	database, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second, OpenFile: func(name string, flag int, mode os.FileMode) (*os.File, error) {
		var e error
		file, e = os.OpenFile(name, flag, mode)
		return file, e
	}})
	if err != nil {
		t.Fatal(err)
	}
	state = &Store{db: database, credits: map[string]int64{}, now: func() time.Time { return *now }}
	original, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Close(original) }()
	full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = full.Close() }()
	if err = syscall.Dup3(int(full.Fd()), int(file.Fd()), 0); err != nil {
		t.Fatal(err)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		t.Helper()
		if e := syscall.Dup3(original, int(file.Fd()), 0); e != nil {
			t.Fatal(e)
		}
		restored = true
	}
	defer func() { restore(); _ = state.Close() }()
	if _, err = state.Reserve("account", "exit", 1); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("reserve did not fail with kernel ENOSPC: %v", err)
	}
	batch.BatchID = uuid.NewString()
	batch.Samples = []Sample{{AccountID: "account", ExitID: "exit", UplinkBytes: 1}}
	if err = state.AppendBatch(batch); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("append did not fail with kernel ENOSPC: %v", err)
	}
	pending, err := state.PendingBatches(10)
	if err != nil || len(pending) != 1 {
		t.Fatalf("disk failure lost queued batch %v %v", pending, err)
	}
	restore()
	if err = state.Close(); err != nil {
		t.Fatal(err)
	}
	state, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	state.now = func() time.Time { return *now }
	left, err := state.Remaining("account", "exit")
	if err != nil || left != ReservationChunk*2 {
		t.Fatalf("ENOSPC returned or spent quota %d %v", left, err)
	}
	pending, err = state.PendingBatches(10)
	if err != nil || len(pending) != 1 {
		t.Fatalf("reopen lost queued batch %v %v", pending, err)
	}
}
