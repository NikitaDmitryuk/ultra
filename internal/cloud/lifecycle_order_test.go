package cloud

import (
	"context"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

type lifecycleTrace struct{ events []string }

type lifecycleRoundTripper func(*http.Request) (*http.Response, error)

func (f lifecycleRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type tracedProvider struct {
	*fakeProvider
	trace *lifecycleTrace
}

func (p *tracedProvider) Create(ctx context.Context, req CreateRequest) (Instance, error) {
	p.trace.events = append(p.trace.events, "create:new")
	return p.fakeProvider.Create(ctx, req)
}

func (p *tracedProvider) Delete(ctx context.Context, id string) error {
	p.trace.events = append(p.trace.events, "delete:"+id)
	return p.fakeProvider.Delete(ctx, id)
}

type tracedProvisioner struct {
	*fakeProvisioner
	trace *lifecycleTrace
}

func (p *tracedProvisioner) Prepare(ctx context.Context, op *Operation) (CreateRequest, error) {
	p.trace.events = append(p.trace.events, "prepare:new")
	return p.fakeProvisioner.Prepare(ctx, op)
}

func (p *tracedProvisioner) Install(ctx context.Context, op *Operation, instance Instance) error {
	p.trace.events = append(p.trace.events, "install:new")
	return p.fakeProvisioner.Install(ctx, op, instance)
}

func (p *tracedProvisioner) Verify(ctx context.Context, op *Operation, instance Instance) error {
	p.trace.events = append(p.trace.events, "verify:new")
	return p.fakeProvisioner.Verify(ctx, op, instance)
}

func (p *tracedProvisioner) Publish(ctx context.Context, op *Operation) error {
	p.trace.events = append(p.trace.events, "publish:new")
	return p.fakeProvisioner.Publish(ctx, op)
}

func (p *tracedProvisioner) ApplyRoute(ctx context.Context, op *Operation) error {
	p.trace.events = append(p.trace.events, "apply:new")
	return p.fakeProvisioner.ApplyRoute(ctx, op)
}

func (p *tracedProvisioner) Unpublish(ctx context.Context, op *Operation) error {
	p.trace.events = append(p.trace.events, "unpublish:"+op.InstanceID)
	return p.fakeProvisioner.Unpublish(ctx, op)
}

func (p *tracedProvisioner) Cleanup(ctx context.Context, op *Operation) error {
	p.trace.events = append(p.trace.events, "cleanup:"+op.InstanceID)
	return p.fakeProvisioner.Cleanup(ctx, op)
}

func TestRegionReplacementPublishesNewBeforeDeletingOld(t *testing.T) {
	ctx := context.Background()
	trace := &lifecycleTrace{}
	api := &tracedProvider{fakeProvider: &fakeProvider{monthly: 5, available: true}, trace: trace}
	provisioner := &tracedProvisioner{fakeProvisioner: &fakeProvisioner{}, trace: trace}
	store := newMemory()
	service := &Service{API: api, Store: store, Provisioner: provisioner}
	old := Operation{ID: "old", InstanceID: "old-vm", State: "ready", Phase: "ready", Charged: true}
	if err := store.Save(ctx, old); err != nil {
		t.Fatal(err)
	}
	offer, err := service.Quote(ctx, 1, "fra", "vc2-1c-1gb", old.ID)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := service.Confirm(ctx, 1, offer.ID)
	if err != nil {
		t.Fatal(err)
	}
	for range 6 {
		if err := service.Step(ctx); err != nil {
			t.Fatal(err)
		}
	}
	gotReplacement, err := store.Get(ctx, replacement.ID)
	if err != nil || gotReplacement.State != "ready" || gotReplacement.Phase != "ready" || gotReplacement.InstanceID != "created" {
		t.Fatalf("replacement not ready after migration: %+v, %v", gotReplacement, err)
	}
	gotOld, err := store.Get(ctx, old.ID)
	if err != nil || gotOld.State != "deleted" || gotOld.Charged {
		t.Fatalf("old server not released: %+v, %v", gotOld, err)
	}
	want := []string{
		"prepare:new", "create:new", "install:new", "verify:new", "publish:new", "apply:new",
		"unpublish:old-vm", "delete:old-vm", "cleanup:old-vm",
	}
	if !reflect.DeepEqual(trace.events, want) {
		t.Fatalf("unexpected migration side-effect order:\n got: %v\nwant: %v", trace.events, want)
	}
}

func TestSuccessfulDeleteUnpublishesDeletesCleansAndReleases(t *testing.T) {
	ctx := context.Background()
	trace := &lifecycleTrace{}
	baseAPI := &fakeProvider{monthly: 5, available: true}
	api := &tracedProvider{fakeProvider: baseAPI, trace: trace}
	provisioner := &tracedProvisioner{fakeProvisioner: &fakeProvisioner{}, trace: trace}
	store := newMemory()
	service := &Service{API: api, Store: store, Provisioner: provisioner}
	op := Operation{ID: "node", InstanceID: "node-vm", State: "ready", Phase: "ready", Charged: true}
	if err := store.Save(ctx, op); err != nil {
		t.Fatal(err)
	}
	if err := service.Action(ctx, 1, op.ID, "delete"); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := service.Step(ctx); err != nil {
			t.Fatal(err)
		}
	}
	got, err := store.Get(ctx, op.ID)
	if err != nil || got.State != "deleted" || got.Phase != "cleanup" || got.Charged {
		t.Fatalf("deleted operation did not release its charge: %+v, %v", got, err)
	}
	if baseAPI.deletes != 1 {
		t.Fatalf("provider delete calls = %d, want 1", baseAPI.deletes)
	}
	want := []string{"unpublish:node-vm", "delete:node-vm", "cleanup:node-vm"}
	if !reflect.DeepEqual(trace.events, want) {
		t.Fatalf("unexpected delete side-effect order: got %v, want %v", trace.events, want)
	}
}

func TestVultrDeleteTreatsMissingInstanceAndFirewallAsSuccess(t *testing.T) {
	var paths []string
	api := NewVultr("test-key")
	api.HTTP = &http.Client{Transport: lifecycleRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", r.Method)
		}
		paths = append(paths, r.URL.Path)
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"error":"not found"}`)),
			Request:    r,
		}, nil
	})}
	for range 2 {
		if err := api.Delete(context.Background(), "missing-instance"); err != nil {
			t.Fatalf("missing instance delete: %v", err)
		}
		if err := api.DeleteFirewall(context.Background(), "missing-firewall"); err != nil {
			t.Fatalf("missing firewall delete: %v", err)
		}
	}
	want := []string{"/v2/instances/missing-instance", "/v2/firewalls/missing-firewall", "/v2/instances/missing-instance", "/v2/firewalls/missing-firewall"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("DELETE paths = %v, want %v", paths, want)
	}
}
