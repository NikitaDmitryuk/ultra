package cloud

import (
	"context"
	"errors"
	"testing"
)

func TestCapacityCountsPhysicalMachinesAndUnreflectedReservations(t *testing.T) {
	for _, tc := range []struct {
		name      string
		op        Operation
		instances []Instance
		want      int
	}{
		{"ambiguous creation", Operation{ID: "op", State: "unknown"}, []Instance{{ID: "a", Tags: []string{"ultra-operation-op"}}, {ID: "b", Tags: []string{"ultra-operation-op"}}}, 2},
		{"known plus duplicate", Operation{ID: "op", State: "ready", InstanceID: "a"}, []Instance{{ID: "a"}, {ID: "b", Tags: []string{"ultra-operation-op"}}}, 2},
		{"missing instance", Operation{ID: "op", State: "pending", InstanceID: "a"}, []Instance{{ID: "b", Tags: []string{"ultra-operation-op"}}}, 2},
		{"unreflected purchase", Operation{ID: "op", State: "pending"}, []Instance{{ID: "b"}}, 2},
		{"duplicate inventory row", Operation{ID: "op", State: "ready", InstanceID: "a"}, []Instance{{ID: "a"}, {ID: "a"}}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, api, _ := testService()
			s.Store.(*memoryStore).ops[tc.op.ID] = tc.op
			api.instances = tc.instances
			got, err := s.capacity(context.Background())
			if err != nil || got != tc.want {
				t.Fatalf("capacity=%d err=%v want=%d", got, err, tc.want)
			}
		})
	}
}

type cancelledResourceCleanup struct {
	fakeProvisioner
	calls int
	fail  bool
}

func (p *cancelledResourceCleanup) Cleanup(context.Context, *Operation) error {
	p.calls++
	if p.fail {
		return ErrUnavailable
	}
	return nil
}

func TestCancelPreparedFirewallRetriesCleanupWithoutPurchase(t *testing.T) {
	ctx := context.Background()
	s, api, _ := testService()
	p := &cancelledResourceCleanup{fail: true}
	s.Provisioner = p
	op := Operation{ID: "op", State: "failed", Phase: "prepare", FirewallID: "firewall"}
	s.Store.(*memoryStore).ops[op.ID] = op
	if err := s.Action(ctx, 1, op.ID, "cancel"); err != nil {
		t.Fatal(err)
	}
	if err := s.Step(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cleanup failure=%v", err)
	}
	failed, _ := s.Store.Get(ctx, op.ID)
	if failed.Phase != "cancel_cleanup" || failed.State != "failed" {
		t.Fatalf("lost cleanup checkpoint: %+v", failed)
	}
	p.fail = false
	if err := s.Action(ctx, 1, op.ID, "retry"); err != nil {
		t.Fatal(err)
	}
	if err := s.Step(ctx); err != nil {
		t.Fatal(err)
	}
	done, _ := s.Store.Get(ctx, op.ID)
	if done.State != "cancelled" || done.Charged || api.creates != 0 || p.prepared != 0 || p.calls != 2 {
		t.Fatalf("unsafe cancellation: op=%+v creates=%d cleanup=%d", done, api.creates, p.calls)
	}
}
