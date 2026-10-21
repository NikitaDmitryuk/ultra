package cloud

import (
	"context"
	"errors"
	"testing"
)

type guardedDeleteProvisioner struct {
	fakeProvisioner
	enabled bool
}

func (p *guardedDeleteProvisioner) Unpublish(context.Context, *Operation) error {
	p.enabled = false
	return nil
}

func (p *guardedDeleteProvisioner) ValidateDelete(_ context.Context, op *Operation) error {
	if op.Phase != "unpublish" && p.enabled {
		return ErrConflict
	}
	return nil
}

func TestDeleteRevalidatesUnpublishedTargetOnResume(t *testing.T) {
	ctx := context.Background()
	s, provider, _ := testService()
	p := &guardedDeleteProvisioner{enabled: true}
	s.Provisioner = p
	s.Store.(*memoryStore).ops["op"] = Operation{
		ID:         "op",
		State:      "pending",
		Phase:      "unpublish",
		InstanceID: "vm",
		ExitID:     "op",
		Charged:    true,
	}
	if err := s.Step(ctx); err != nil {
		t.Fatal(err)
	}
	p.enabled = true // legacy checkpoint or out-of-band republish before restart
	if err := s.Step(ctx); !errors.Is(err, ErrConflict) {
		t.Fatalf("republished target accepted: %v", err)
	}
	if provider.deletes != 0 {
		t.Fatal("republished VPS was deleted")
	}
	op, _ := s.Store.Get(ctx, "op")
	if op.Phase != "delete" || op.State != "failed" {
		t.Fatalf("lost checkpoint: %+v", op)
	}
}
