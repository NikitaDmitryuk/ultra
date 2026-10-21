package cloud

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type orderedRetirementStore struct {
	Store
	topologyHeld *bool
	locks        int
}

func (s *orderedRetirementStore) Lock(ctx context.Context) (func(), error) {
	if !*s.topologyHeld {
		return nil, errors.New("store lock acquired before topology")
	}
	s.locks++
	return s.Store.Lock(ctx)
}
func TestRetirementAndWorkerAcquireTopologyBeforeStore(t *testing.T) {
	s, api, _, targets := retirementFixture(t)
	held := false
	store := &orderedRetirementStore{Store: s.Store, topologyHeld: &held}
	s.Store = store
	s.LockTopology = func(ctx context.Context) (func(), error) {
		if held {
			t.Fatal("recursive topology acquisition")
		}
		held = true
		return func() { held = false }, nil
	}
	api.failed = "vm-a"
	ctx := context.Background()
	if err := s.RetireExits(ctx, 1, targets[:1]); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	s.Store = store.Store
	if err := s.Action(ctx, 1, "a", "delete"); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if err := s.Action(ctx, 1, "a", "retry"); err != nil {
		t.Fatal(err)
	}
	s.Store = store
	api.failed = ""
	for range 2 {
		if err := s.Step(ctx); err != nil {
			t.Fatal(err)
		}
	}
	op, _ := s.Store.Get(ctx, "a")
	if held || store.locks != 3 || op.State != "deleted" {
		t.Fatalf("held=%v locks=%d op=%+v", held, store.locks, op)
	}
}
func TestRetirementCancelledTopologyLeaseDoesNotTakeStoreLock(t *testing.T) {
	s, _, _, targets := retirementFixture(t)
	s.LockTopology = func(context.Context) (func(), error) { return nil, context.Canceled }
	for _, run := range []func() error{
		func() error { return s.Step(context.Background()) },
		func() error { return s.RetireExits(context.Background(), 1, targets) },
	} {
		if err := run(); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
}

func TestRetirementWorkerWaitsForTopologyMutation(t *testing.T) {
	s, _, _, _ := retirementFixture(t)
	var topology sync.Mutex
	topology.Lock()
	waiting := make(chan struct{})
	done := make(chan error, 1)
	s.LockTopology = func(context.Context) (func(), error) {
		close(waiting)
		topology.Lock()
		return topology.Unlock, nil
	}
	go func() { done <- s.Step(context.Background()) }()
	<-waiting
	select {
	case err := <-done:
		t.Fatalf("worker bypassed topology mutation: %v", err)
	default:
	}
	topology.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker deadlocked after topology mutation")
	}
}
