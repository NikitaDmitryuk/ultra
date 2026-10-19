package cloud

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type retirementGateStore struct {
	Store
	saves, audits int
}

func (s *retirementGateStore) Save(ctx context.Context, op Operation) error {
	s.saves++
	return s.Store.Save(ctx, op)
}

func (s *retirementGateStore) Audit(ctx context.Context, actor int64, id, action string) error {
	s.audits++
	return s.Store.Audit(ctx, actor, id, action)
}

type retirementGateProvider struct {
	Provider
	reads int
}

func (p *retirementGateProvider) Instances(ctx context.Context) ([]Instance, error) {
	p.reads++
	return p.Provider.Instances(ctx)
}

// The ordinary retirement API cannot authorize work inside an upgrade's applying
// reservation. A saved retirement phase is a checkpoint, not lifecycle authority.
func TestRetirementApplyingLifecycleBlocksInitialAndResumedDeletion(t *testing.T) {
	for _, phase := range []string{"ready", "retire_unpublish", "retire_delete", "retire_cleanup"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			s, provider, provisioner, targets := retirementFixture(t)
			before, err := s.Store.Get(ctx, targets[0].OperationID)
			if err != nil {
				t.Fatal(err)
			}
			before.Phase = phase
			if phase != "ready" {
				before.State = "failed"
			}
			if err := s.Store.Save(ctx, before); err != nil {
				t.Fatal(err)
			}
			store := &retirementGateStore{Store: s.Store}
			api := &retirementGateProvider{Provider: s.API}
			s.Store, s.API = store, api
			busy := errors.New("lifecycle_busy")
			gateCalls := 0
			s.TopologyReady = func(context.Context) error {
				gateCalls++
				return busy
			}
			if err := s.RetireExits(ctx, 1, targets[:1]); !errors.Is(err, busy) {
				t.Fatalf("retirement bypassed applying reservation: %v", err)
			}
			after, err := store.Get(ctx, before.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) || store.saves != 0 || store.audits != 0 {
				t.Fatalf("closed gate changed retirement checkpoint: before=%+v after=%+v saves=%d audits=%d", before, after, store.saves, store.audits)
			}
			if gateCalls != 1 || api.reads != 0 || provider.deletes != 0 || provisioner.unpublished != 0 {
				t.Fatalf("retirement advanced through closed gate: gate=%d inventory=%d delete=%d unpublish=%d", gateCalls, api.reads, provider.deletes, provisioner.unpublished)
			}
		})
	}
}
