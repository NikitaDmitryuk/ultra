package cloud

import (
	"context"
	"errors"
	"testing"
)

func TestIngressProtection(t *testing.T) {
	ctx := context.Background()
	s, api, provisioner := testService()
	old := Operation{ID: "old", InstanceID: "ingress", State: "ready", Phase: "ready"}
	if err := s.Store.Save(ctx, old); err != nil {
		t.Fatal(err)
	}
	offer, err := s.Quote(ctx, 1, "fra", "vc2-1c-1gb", old.ID)
	if err != nil {
		t.Fatal(err)
	}
	s.IngressInstanceID = "ingress"
	if _, err = s.Quote(ctx, 1, "fra", "vc2-1c-1gb", old.ID); !errors.Is(err, ErrIngressInUse) {
		t.Fatalf("quote: %v", err)
	}
	if _, err = s.Confirm(ctx, 1, offer.ID); !errors.Is(err, ErrIngressInUse) {
		t.Fatalf("stale offer: %v", err)
	}
	if err = s.Action(ctx, 1, old.ID, "delete"); !errors.Is(err, ErrIngressInUse) {
		t.Fatalf("delete: %v", err)
	}
	for _, phase := range []string{"prepare", "replace_old"} {
		op := Operation{ID: "replacement", State: "pending", Phase: phase, Offer: offer}
		if err = s.advance(ctx, op); !errors.Is(err, ErrIngressInUse) {
			t.Fatalf("replacement %s: %v", phase, err)
		}
	}
	for _, phase := range []string{"unpublish", "delete", "cleanup"} {
		old.State = "pending"
		old.Phase = phase
		if err = s.Store.Save(ctx, old); err != nil {
			t.Fatal(err)
		}
		// A new worker object restores the guard from configuration after restart.
		restarted := &Service{API: api, Store: s.Store, Provisioner: s.Provisioner, IngressInstanceID: "ingress"}
		if err = restarted.Step(ctx); !errors.Is(err, ErrIngressInUse) {
			t.Fatalf("resume %s: %v", phase, err)
		}
		got, _ := s.Store.Get(ctx, old.ID)
		if got.State != "failed" || got.Error != "ingress_in_use" {
			t.Fatalf("unexpected result: %+v", got)
		}
	}
	if provisioner.prepared != 0 || provisioner.unpublished != 0 {
		t.Fatal("protected infrastructure was touched")
	}
	if api.creates != 0 || api.deletes != 0 {
		t.Fatalf("provider mutated: %d/%d", api.creates, api.deletes)
	}
	s.IngressInstanceID = "another"
	if err = s.Action(ctx, 1, old.ID, "delete"); err != nil {
		t.Fatalf("unrelated node blocked: %v", err)
	}
}

type unavailableReplacementStore struct{ Store }

func (s unavailableReplacementStore) Get(context.Context, string) (Operation, error) {
	return Operation{}, context.DeadlineExceeded
}

func TestReplacementLookupFailureIsNotIngressConflict(t *testing.T) {
	s, api, provisioner := testService()
	store := s.Store
	s.Store = unavailableReplacementStore{store}
	err := s.advance(context.Background(), Operation{ID: "replacement", Phase: "prepare", Offer: Offer{ReplaceID: "old"}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	op, err := store.Get(context.Background(), "replacement")
	if err != nil || op.Error != "operation_timeout" {
		t.Fatalf("wrong error classification: %q, %v", op.Error, err)
	}
	if api.creates != 0 || api.deletes != 0 || provisioner.prepared != 0 {
		t.Fatal("resource mutation after failed ownership lookup")
	}
}
