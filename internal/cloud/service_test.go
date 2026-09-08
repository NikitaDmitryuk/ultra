package cloud

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type memoryStore struct {
	events []Event
	mu     sync.Mutex
	offers map[string]Offer
	ops    map[string]Operation
}

func newMemory() *memoryStore {
	return &memoryStore{offers: map[string]Offer{}, ops: map[string]Operation{}}
}
func (m *memoryStore) SaveOffer(_ context.Context, o Offer) error { m.offers[o.ID] = o; return nil }
func (m *memoryStore) Offer(_ context.Context, id string) (Offer, error) {
	v, ok := m.offers[id]
	if !ok {
		return v, ErrConflict
	}
	return v, nil
}
func (m *memoryStore) Get(_ context.Context, id string) (Operation, error) {
	v, ok := m.ops[id]
	if !ok {
		return v, ErrConflict
	}
	return v, nil
}
func (m *memoryStore) List(context.Context) ([]Operation, error) {
	out := []Operation{}
	for _, o := range m.ops {
		out = append(out, o)
	}
	return out, nil
}
func (m *memoryStore) Reserve(_ context.Context, o Offer) (Operation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.ops) >= 2 {
		return Operation{}, ErrLimit
	}
	v := Operation{ID: o.ID, Offer: o, State: "pending", Phase: "prepare"}
	m.ops[v.ID] = v
	return v, nil
}
func (m *memoryStore) Save(_ context.Context, o Operation) error          { m.ops[o.ID] = o; return nil }
func (m *memoryStore) Lock(context.Context) (func(), error)               { return func() {}, nil }
func (m *memoryStore) Audit(context.Context, int64, string, string) error { return nil }

type fakeProvider struct {
	creates, deletes int
	unknown          bool
	monthly          float64
	available        bool
	instances        []Instance
}

func (p *fakeProvider) Regions(context.Context) ([]Region, error) {
	return []Region{{ID: "fra", City: "Frankfurt", Country: "DE"}}, nil
}
func (p *fakeProvider) Plans(context.Context) ([]Plan, error) {
	return []Plan{{ID: "vc2-1c-1gb", RAM: 1024, CPU: 1, Cost: Cost{Monthly: p.monthly, Hourly: .007}}}, nil
}
func (p *fakeProvider) Available(context.Context, string, string) (bool, error) {
	return p.available, nil
}
func (p *fakeProvider) Create(context.Context, CreateRequest) (Instance, error) {
	p.creates++
	if p.unknown {
		return Instance{}, ErrUnknownCreation
	}
	return Instance{ID: "created"}, nil
}
func (p *fakeProvider) Instances(context.Context) ([]Instance, error) { return p.instances, nil }
func (p *fakeProvider) Get(context.Context, string) (Instance, error) {
	return Instance{ID: "created", Status: "active", IP: "192.0.2.1"}, nil
}
func (p *fakeProvider) Delete(context.Context, string) error { p.deletes++; return nil }

type fakeProvisioner struct {
	prepared, unpublished   int
	verified, published     bool
	failVerify, failPublish bool
}

func (p *fakeProvisioner) Prepare(context.Context, *Operation) (CreateRequest, error) {
	p.prepared++
	return CreateRequest{}, nil
}
func (p *fakeProvisioner) Install(_ context.Context, o *Operation, _ Instance) error {
	o.ExitID = "staged"
	return nil
}
func (p *fakeProvisioner) Verify(context.Context, *Operation, Instance) error {
	if p.failVerify {
		return ErrUnavailable
	}
	p.verified = true
	return nil
}
func (p *fakeProvisioner) Publish(context.Context, *Operation) error {
	if !p.verified {
		panic("published before verification")
	}
	if p.failPublish {
		return ErrUnavailable
	}
	p.published = true
	return nil
}
func (p *fakeProvisioner) Unpublish(context.Context, *Operation) error { p.unpublished++; return nil }
func (p *fakeProvisioner) Cleanup(context.Context, *Operation) error   { return nil }
func testService() (*Service, *fakeProvider, *fakeProvisioner) {
	api := &fakeProvider{monthly: 5, available: true}
	p := &fakeProvisioner{}
	return &Service{API: api, Store: newMemory(), Provisioner: p}, api, p
}
func TestOfferValidation(t *testing.T) {
	ctx := context.Background()
	s, api, _ := testService()
	offer, e := s.Quote(ctx, 1, "fra", "vc2-1c-1gb", "")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Confirm(ctx, 2, offer.ID); !errors.Is(e, ErrConflict) {
		t.Fatal("wrong actor accepted")
	}
	api.monthly = 6
	if _, e = s.Confirm(ctx, 1, offer.ID); !errors.Is(e, ErrPriceChanged) {
		t.Fatal("changed price accepted")
	}
	api.monthly = 5
	s.Now = func() time.Time { return offer.ExpiresAt }
	if _, e = s.Confirm(ctx, 1, offer.ID); !errors.Is(e, ErrPriceChanged) {
		t.Fatal("expired offer accepted")
	}
	if api.creates != 0 {
		t.Fatal("quote validation created resource")
	}
}
func TestUnknownCreationNeverBuysTwice(t *testing.T) {
	ctx := context.Background()
	s, api, p := testService()
	api.unknown = true
	offer, e := s.Quote(ctx, 1, "fra", "vc2-1c-1gb", "")
	if e != nil {
		t.Fatal(e)
	}
	op, e := s.Confirm(ctx, 1, offer.ID)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 4; i++ {
		_ = s.Step(ctx)
	}
	if api.creates != 1 || p.published {
		t.Fatal("unsafe retry")
	}
	api.instances = []Instance{{ID: "found", Region: "fra", Plan: "vc2-1c-1gb", Tags: []string{"ultra-operation-" + op.ID}}}
	for i := 0; i < 4; i++ {
		if e = s.Step(ctx); e != nil {
			t.Fatal(e)
		}
	}
	saved, e := s.Store.Get(ctx, op.ID)
	if e != nil || saved.State != "ready" || !p.published || api.creates != 1 {
		t.Fatal("recovery failed", saved.State, e)
	}
	if _, e = s.Confirm(ctx, 1, offer.ID); e != nil {
		t.Fatal("idempotent confirmation failed", e)
	}
}
func TestVerificationAndApplyFailuresKeepNodeUnpublished(t *testing.T) {
	for _, phase := range []string{"verify", "publish"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			s, api, p := testService()
			p.failVerify = phase == "verify"
			p.failPublish = phase == "publish"
			offer, e := s.Quote(ctx, 1, "fra", "vc2-1c-1gb", "")
			if e != nil {
				t.Fatal(e)
			}
			op, e := s.Confirm(ctx, 1, offer.ID)
			if e != nil {
				t.Fatal(e)
			}
			for i := 0; i < 4; i++ {
				_ = s.Step(ctx)
			}
			saved, _ := s.Store.Get(ctx, op.ID)
			if saved.State != "failed" || p.published {
				t.Fatal("failed node published")
			}
			p.failVerify = false
			p.failPublish = false
			if e = s.Action(ctx, 1, op.ID, "retry"); e != nil {
				t.Fatal(e)
			}
			for i := 0; i < 3; i++ {
				if e = s.Step(ctx); e != nil {
					t.Fatal(e)
				}
			}
			if !p.published || api.creates != 1 {
				t.Fatal("retry did not resume")
			}
		})
	}
}
func TestLocationCostOverridesBase(t *testing.T) {
	p := Plan{Cost: Cost{Monthly: 5}, LocationCost: map[string]Cost{"sao": {Monthly: 7.5}}}
	if p.Price("sao").Monthly != 7.5 || p.Price("fra").Monthly != 5 {
		t.Fatal("wrong regional price")
	}
}

func (m *memoryStore) RecordEvent(_ context.Context, e Event) error {
	m.events = append(m.events, e)
	return nil
}
func (m *memoryStore) Events(context.Context, string) ([]Event, error) { return m.events, nil }
