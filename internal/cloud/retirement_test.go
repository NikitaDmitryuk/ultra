package cloud

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type retirementProvider struct {
	*fakeProvider
	failed string
}

func (p *retirementProvider) Get(_ context.Context, id string) (Instance, error) {
	for _, instance := range p.instances {
		if instance.ID == id {
			return instance, nil
		}
	}
	return Instance{}, APIError{Status: 404}
}

func (p *retirementProvider) Delete(_ context.Context, id string) error {
	p.deletes++
	if p.failed == id {
		return ErrUnavailable
	}
	for i, instance := range p.instances {
		if instance.ID == id {
			p.instances = append(p.instances[:i], p.instances[i+1:]...)
			break
		}
	}
	return nil
}

type retirementProvisioner struct {
	*fakeProvisioner
	protected string
}

func (p *retirementProvisioner) ValidateRetirement(_ context.Context, op *Operation, _ Instance) error {
	if op.ID == p.protected {
		return ErrConflict
	}
	return nil
}

func retirementFixture(t *testing.T) (*Service, *retirementProvider, *retirementProvisioner, []RetirementTarget) {
	t.Helper()
	s, base, provisioner := testService()
	api := &retirementProvider{fakeProvider: base}
	p := &retirementProvisioner{fakeProvisioner: provisioner}
	s.API, s.Provisioner = api, p
	targets := []RetirementTarget{}
	for _, id := range []string{"a", "b"} {
		op := Operation{ID: id, InstanceID: "vm-" + id, ExitID: id, State: "ready", Phase: "ready", Charged: true}
		if err := s.Store.Save(context.Background(), op); err != nil {
			t.Fatal(err)
		}
		api.instances = append(
			api.instances,
			Instance{ID: op.InstanceID, IP: "192.0.2.2", Tags: []string{"ultra", "ultra-operation-" + id}},
		)
		targets = append(targets, RetirementTarget{OperationID: id, InstanceID: op.InstanceID})
	}
	api.instances = append(api.instances, Instance{ID: "unmanaged"})
	return s, api, p, targets
}

func TestRetirementPartialFailureAndReplay(t *testing.T) {
	s, api, provisioner, targets := retirementFixture(t)
	api.failed = "vm-a"
	ctx := context.Background()
	if err := s.RetireExits(ctx, 1, targets); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	a, _ := s.Store.Get(ctx, "a")
	b, _ := s.Store.Get(ctx, "b")
	if a.State != "failed" || a.Phase != "retire_delete" || !a.Charged || b.State != "deleted" || b.Charged {
		t.Fatalf("partial checkpoints: %+v / %+v", a, b)
	}
	api.failed = ""
	if err := s.RetireExits(ctx, 1, targets); err != nil {
		t.Fatal(err)
	}
	deletes, unpublishes := api.deletes, provisioner.unpublished
	if err := s.RetireExits(ctx, 1, targets); err != nil {
		t.Fatal(err)
	}
	if api.deletes != deletes || provisioner.unpublished != unpublishes || len(api.instances) != 1 || api.instances[0].ID != "unmanaged" {
		t.Fatalf("replay mutated completed or unmanaged resources: %+v", api)
	}
	for _, id := range []string{"a", "b"} {
		op, _ := s.Store.Get(ctx, id)
		events, _ := s.Store.Events(ctx, id)
		if op.State != "deleted" || op.ExitID != id || len(events) == 0 {
			t.Fatalf("history/tombstone lost: %+v, events=%d", op, len(events))
		}
	}
}

func TestRetirementFailsClosedBeforeAnyMutation(t *testing.T) {
	for _, scenario := range []string{"instance", "tag", "extra-tag", "ingress", "persisted-ingress", "main", "exit", "reinstall", "empty-ip", "ipv6", "saved-target"} {
		t.Run(scenario, func(t *testing.T) {
			s, api, provisioner, targets := retirementFixture(t)
			op, _ := s.Store.Get(context.Background(), "b")
			switch scenario {
			case "instance":
				targets[1].InstanceID = "unmanaged"
			case "tag":
				api.instances[1].Tags = []string{"ultra", "ultra-operation-a"}
			case "extra-tag":
				api.instances[1].Tags = append(api.instances[1].Tags, "main")
			case "ingress":
				s.IngressInstanceID = op.InstanceID
			case "persisted-ingress":
				op.ServesSubscriptionIngress = true
			case "main":
				provisioner.protected = op.ID
			case "exit":
				op.ExitID = "static-main"
			case "reinstall":
				op.ReinstallTarget = "reserved"
			case "empty-ip":
				api.instances[1].IP = ""
			case "ipv6":
				api.instances[1].IP = "2001:db8::1"
			case "saved-target":
				op.RetirementTarget = api.instances[1].IP
			}
			_ = s.Store.Save(context.Background(), op)
			if err := s.RetireExits(context.Background(), 1, targets); err == nil {
				t.Fatal("accepted unsafe plan")
			}
			if api.deletes != 0 || provisioner.unpublished != 0 {
				t.Fatal("mutated before whole plan validation")
			}
		})
	}
}

func TestRetirementResumeRechecksOwnership(t *testing.T) {
	s, api, provisioner, _ := retirementFixture(t)
	op, _ := s.Store.Get(context.Background(), "a")
	op.State, op.Phase = "pending", "retire_delete"
	op.RetirementTarget = api.instances[0].IP
	_ = s.Store.Save(context.Background(), op)
	api.instances[0].Tags = []string{"ultra", "ultra-operation-b"}
	if err := s.Step(context.Background()); err == nil {
		t.Fatal("resume accepted changed ownership")
	}
	if api.deletes != 0 || provisioner.unpublished != 0 {
		t.Fatal("resume mutated mismatched resource")
	}
}

func TestRetirementWorkerResumesAfterProviderDisappears(t *testing.T) {
	s, api, _, _ := retirementFixture(t)
	ctx := context.Background()
	op, _ := s.Store.Get(ctx, "a")
	op.State, op.Phase = "pending", "retire_delete"
	op.RetirementTarget = api.instances[0].IP
	_ = s.Store.Save(ctx, op)
	api.instances = api.instances[1:]
	for range 2 {
		if err := s.Step(ctx); err != nil {
			t.Fatal(err)
		}
	}
	op, _ = s.Store.Get(ctx, "a")
	if op.State != "deleted" || op.Charged || api.deletes != 0 {
		t.Fatalf("missing provider resume: %+v deletes=%d", op, api.deletes)
	}
}

func TestRetirementIncludesUninstalledPaidInstance(t *testing.T) {
	s, _, provisioner, targets := retirementFixture(t)
	ctx := context.Background()
	op, _ := s.Store.Get(ctx, "a")
	op.State, op.Phase, op.ExitID = "pending", "install", ""
	_ = s.Store.Save(ctx, op)
	if err := s.RetireExits(ctx, 1, targets); err != nil {
		t.Fatal(err)
	}
	op, _ = s.Store.Get(ctx, "a")
	if op.State != "deleted" || op.RetirementTarget != "192.0.2.2" || provisioner.prepared != 0 {
		t.Fatalf("uninstalled paid resource not retired: %+v", op)
	}
}

func TestRetirementRejectsMissingOrChangedSavedAddress(t *testing.T) {
	for _, phase := range []string{"retire_unpublish", "retire_delete", "retire_cleanup"} {
		for _, saved := range []string{"", "192.0.2.9"} {
			for _, missing := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/saved=%s/missing=%t", phase, saved, missing), func(t *testing.T) {
					s, api, provisioner, targets := retirementFixture(t)
					ctx := context.Background()
					op, _ := s.Store.Get(ctx, "a")
					op.State, op.Phase, op.RetirementTarget = "pending", phase, saved
					_ = s.Store.Save(ctx, op)
					if missing {
						api.instances = api.instances[1:]
					}
					// With provider 404 the saved address is authoritative; changed
					// provider addresses are only detectable while it still exists.
					if missing && saved != "" {
						return
					}
					if err := s.RetireExits(ctx, 1, targets[:1]); !errors.Is(err, ErrConflict) {
						t.Fatalf("replay accepted invalid checkpoint: %v", err)
					}
					if err := s.Step(ctx); err == nil {
						t.Fatal("worker accepted invalid checkpoint")
					}
					if api.deletes != 0 || provisioner.unpublished != 0 {
						t.Fatal("invalid checkpoint mutated resources")
					}
				})
			}
		}
	}
}

func TestRetirementUsesPaginatedInventoryBeforeCheckpoint(t *testing.T) {
	s, _, _, _ := retirementFixture(t)
	pages := 0
	transport := lifecycleRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || r.URL.Path != "/instances" {
			t.Fatalf("unexpected mutation: %s %s", r.Method, r.URL)
		}
		pages++
		if r.URL.Query().Get("cursor") == "" {
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(`{"instances":[{"id":"unmanaged"}],"meta":{"links":{"next":"next-page"}}}`)),
			}, nil
		}
		return &http.Response{
			StatusCode: 200,
			Body: io.NopCloser(
				strings.NewReader(`{"instances":[{"id":"vm-a","tags":["ultra","wrong-operation"]}],"meta":{"links":{"next":""}}}`),
			),
		}, nil
	})
	s.API = &Vultr{BaseURL: "https://provider.example", HTTP: &http.Client{Transport: transport}}
	if err := s.RetireExits(context.Background(), 1, []RetirementTarget{{OperationID: "a", InstanceID: "vm-a"}}); err == nil {
		t.Fatal("accepted ownership mismatch on page two")
	}
	op, _ := s.Store.Get(context.Background(), "a")
	if pages != 2 || op.Phase != "ready" {
		t.Fatalf("incomplete inventory/checkpoint: pages=%d operation=%+v", pages, op)
	}
}
