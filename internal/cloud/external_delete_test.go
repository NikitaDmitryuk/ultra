package cloud

import (
	"context"
	"errors"
	"testing"
)

type removedInstanceProvider struct{ *fakeProvider }

func (p removedInstanceProvider) Get(context.Context, string) (Instance, error) {
	return Instance{}, APIError{Status: 404, Code: "not_found"}
}
func TestExternalInstanceDeletionNeverAutomaticallyPurchasesReplacement(t *testing.T) {
	for _, phase := range []string{"ready", "install", "verify"} {
		t.Run(phase, func(t *testing.T) {
			s, api, _ := testService()
			s.API = removedInstanceProvider{api}
			state := "pending"
			if phase == "ready" {
				state = "ready"
			}
			op := Operation{ID: "removed", InstanceID: "externally-deleted", State: state, Phase: phase, Charged: true}
			s.Store.(*memoryStore).ops[op.ID] = op
			for range 5 {
				_ = s.Step(context.Background())
			}
			got, _ := s.Store.Get(context.Background(), op.ID)
			if phase != "ready" {
				if got.State != "failed" || got.Phase != phase {
					t.Fatalf("404 changed phase toward purchase: %v", got)
				}
				if err := s.Action(context.Background(), 1, op.ID, "retry"); err != nil {
					t.Fatal(err)
				}
				_ = s.Step(context.Background())
			} else if err := s.Action(context.Background(), 1, op.ID, "retry"); !errors.Is(err, ErrConflict) {
				t.Fatalf("ready retry unexpectedly allowed %v", err)
			}
			if api.creates != 0 {
				t.Fatalf("automatically bought %d replacement instances", api.creates)
			}
		})
	}
}
