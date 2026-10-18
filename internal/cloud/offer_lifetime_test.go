package cloud

import (
	"context"
	"errors"
	"testing"
	"time"
)

type prepareHookProvisioner struct {
	*fakeProvisioner
	hook func()
}

func (p prepareHookProvisioner) Prepare(ctx context.Context, op *Operation) (CreateRequest, error) {
	p.hook()
	return p.fakeProvisioner.Prepare(ctx, op)
}

func TestConfirmedOfferSurvivesQueueAndPreparationDelay(t *testing.T) {
	for _, replace := range []string{"", "old"} {
		for _, delay := range []string{"queue", "prepare"} {
			t.Run(replace+"/"+delay, func(t *testing.T) {
				ctx := context.Background()
				s, api, provisioner := testService()
				now := time.Now().UTC()
				s.Now = func() time.Time { return now }
				if replace != "" {
					s.Store.(*memoryStore).ops[replace] = Operation{ID: replace, State: "ready", Phase: "ready", InstanceID: "old-vm"}
				}
				offer, err := s.Quote(ctx, 1, "fra", "vc2-1c-1gb", replace)
				if err != nil {
					t.Fatal(err)
				}
				op, err := s.Confirm(ctx, 1, offer.ID)
				if err != nil {
					t.Fatal(err)
				}
				expire := func() { now = offer.ExpiresAt.Add(time.Minute) }
				if delay == "queue" {
					expire()
				} else {
					s.Provisioner = prepareHookProvisioner{provisioner, expire}
				}
				for range 7 {
					if err := s.Step(ctx); err != nil {
						t.Fatal(err)
					}
				}
				saved, err := s.Store.Get(ctx, op.ID)
				if err != nil || saved.State != "ready" || api.creates != 1 || !provisioner.published {
					t.Fatalf("confirmed purchase did not complete: op=%+v creates=%d err=%v", saved, api.creates, err)
				}
				if api.deletes != btoi(replace != "") {
					t.Fatalf("replacement deleted wrong number of VMs: %d", api.deletes)
				}
			})
		}
	}
}

func TestConfirmedOfferRevalidatesBeforeAndAfterPreparation(t *testing.T) {
	for _, stage := range []string{"queue", "prepare"} {
		for _, change := range []string{"price", "availability"} {
			t.Run(stage+"/"+change, func(t *testing.T) {
				ctx := context.Background()
				s, api, provisioner := testService()
				offer, err := s.Quote(ctx, 1, "fra", "vc2-1c-1gb", "")
				if err != nil {
					t.Fatal(err)
				}
				op, err := s.Confirm(ctx, 1, offer.ID)
				if err != nil {
					t.Fatal(err)
				}
				mutate := func() {
					if change == "price" {
						api.monthly = 4 // Even a lower price requires a fresh offer.
					} else {
						api.available = false
					}
				}
				if stage == "queue" {
					mutate()
				} else {
					s.Provisioner = prepareHookProvisioner{provisioner, mutate}
				}
				s.Now = func() time.Time { return offer.ExpiresAt.Add(time.Minute) }
				if err := s.Step(ctx); !errors.Is(err, ErrPriceChanged) {
					t.Fatalf("changed offer accepted: %v", err)
				}
				saved, _ := s.Store.Get(ctx, op.ID)
				if saved.State != "failed" || saved.Phase != "prepare" || api.creates != 0 || provisioner.prepared != btoi(stage == "prepare") {
					t.Fatalf("purchase escaped revalidation: op=%+v creates=%d prepared=%d", saved, api.creates, provisioner.prepared)
				}
			})
		}
	}
}
