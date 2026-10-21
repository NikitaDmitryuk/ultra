package cloud

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestDeleteReplayPreservesCheckpointAndTombstone(t *testing.T) {
	for _, state := range []string{"pending", "failed", "deleted"} {
		for _, phase := range []string{"unpublish", "delete", "cleanup"} {
			t.Run(state+"/"+phase, func(t *testing.T) {
				s, provider, provisioner := testService()
				store := s.Store.(*memoryStore)
				op := Operation{ID: "op", InstanceID: "vm", ExitID: "exit", State: state, Phase: phase, Charged: state != "deleted"}
				if state == "failed" {
					op.Error, op.ErrorMessage, op.HTTPStatus = "resource_cleanup_failed", "safe diagnostic", 503
				}
				store.ops[op.ID] = op
				if err := s.Action(context.Background(), 1, op.ID, "delete"); err != nil {
					t.Fatal(err)
				}
				got := store.ops[op.ID]
				if state == "failed" {
					op.State, op.Error, op.ErrorMessage, op.HTTPStatus = "pending", "", "", 0
				}
				if !reflect.DeepEqual(got, op) {
					t.Fatalf("replay changed saved checkpoint: got %+v want %+v", got, op)
				}
				if provider.creates != 0 || provider.deletes != 0 || provisioner.unpublished != 0 {
					t.Fatal("action performed worker effects")
				}
			})
		}
	}
}

type failingCleanup struct {
	*fakeProvisioner
	calls int
}

func (p *failingCleanup) Cleanup(context.Context, *Operation) error {
	p.calls++
	if p.calls == 1 {
		return ErrUnavailable
	}
	return nil
}

func TestDeleteResumesAfterCleanupFailureWithoutRewinding(t *testing.T) {
	s, provider, provisioner := testService()
	cleanup := &failingCleanup{fakeProvisioner: provisioner}
	s.Provisioner = cleanup
	store := s.Store.(*memoryStore)
	// Deleting an in-progress installation must still enqueue its first removal.
	store.ops["op"] = Operation{ID: "op", InstanceID: "vm", State: "pending", Phase: "install", Charged: true}
	ctx := context.Background()
	if err := s.Action(ctx, 1, "op", "delete"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.Step(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Step(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected cleanup failure: %v", err)
	}
	if err := s.Action(ctx, 1, "op", "delete"); err != nil {
		t.Fatal(err)
	}
	if err := s.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Action(ctx, 1, "op", "delete"); err != nil {
		t.Fatal(err)
	}
	if err := s.Step(ctx); err != nil {
		t.Fatal(err)
	}
	got := store.ops["op"]
	if got.State != "deleted" || got.Charged || provider.deletes != 1 || provisioner.unpublished != 1 || cleanup.calls != 2 {
		t.Fatalf("deletion replayed completed effects: op=%+v deletes=%d unpublish=%d cleanup=%d", got, provider.deletes, provisioner.unpublished, cleanup.calls)
	}
}

type replayCapacityStore struct {
	*memoryStore
	reserved Operation
}

func (s *replayCapacityStore) LockCapacity(context.Context) (func(), error) {
	// Another confirmation wins while this caller waits for the capacity lock.
	s.ops[s.reserved.ID] = s.reserved
	return func() {}, nil
}

func TestConcurrentConfirmReturnsExistingOperationAtCapacity(t *testing.T) {
	for _, actor := range []int64{1, 2} {
		t.Run(map[int64]string{1: "same_actor", 2: "different_actor"}[actor], func(t *testing.T) {
			s, provider, _ := testService()
			ctx := context.Background()
			offer, err := s.Quote(ctx, 1, "fra", "vc2-1c-1gb", "")
			if err != nil {
				t.Fatal(err)
			}
			store := &replayCapacityStore{memoryStore: s.Store.(*memoryStore), reserved: Operation{
				ID: offer.ID, Offer: offer, State: "pending", Phase: "prepare",
			}}
			store.reserved.Offer.Actor = actor
			s.Store = store
			provider.instances = []Instance{{ID: "one"}, {ID: "two"}, {ID: "three"}, {ID: "four"}}
			op, err := s.Confirm(ctx, 1, offer.ID)
			if actor != 1 {
				if !errors.Is(err, ErrConflict) {
					t.Fatalf("actor conflict: %v", err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(op, store.reserved) {
				t.Fatalf("concurrent confirmation lost original reservation: %+v, %v", op, err)
			}
			if provider.creates != 0 || len(store.ops) != 1 {
				t.Fatal("replayed confirmation created a resource")
			}
		})
	}
}
