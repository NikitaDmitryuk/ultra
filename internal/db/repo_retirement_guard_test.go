package db

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
)

func TestRetirementReservationProtectsFailedAndDeletedExit(t *testing.T) {
	for _, state := range []string{"pending", "failed", "deleted"} {
		for _, phase := range []string{"retire_unpublish", "retire_delete", "retire_cleanup", "delete", "cleanup"} {
			t.Run(state+"/"+phase, func(t *testing.T) {
				database, repo, op, node, _ := reinstallGuardFixture(t)
				ctx := context.Background()
				op.Reinstall, op.State, op.Phase = false, state, phase
				op.RetirementTarget = node.Address
				if err := NewCloudRepo(database).Save(ctx, op); err != nil {
					t.Fatal(err)
				}
				enabled := true
				name := "changed"
				for _, patch := range []exits.UpdatePatch{{Enabled: &enabled}, {Name: &name}} {
					if _, err := repo.Update(ctx, node.ID, patch); !errors.Is(err, ErrExitTargetBusy) {
						t.Fatalf("mutation escaped reservation: %v", err)
					}
				}
				if err := repo.Delete(ctx, node.ID); !errors.Is(err, ErrExitTargetBusy) {
					t.Fatalf("delete escaped reservation: %v", err)
				}
				_, err := repo.Add(ctx, exits.AddParams{Name: "alias", Address: node.Address, Port: node.Port + 1})
				if state == "deleted" && (phase == "delete" || phase == "cleanup") {
					if err != nil {
						t.Fatalf("completed ordinary deletion retained address: %v", err)
					}
				} else if !errors.Is(err, ErrExitTargetBusy) {
					t.Fatalf("alias escaped reservation: %v", err)
				}
				err = repo.DisableCloudRetirement(ctx, &op)
				if state == "pending" && phase == "retire_unpublish" {
					if err != nil {
						t.Fatalf("internal disable failed: %v", err)
					}
				} else if err == nil {
					t.Fatal("internal disable accepted outside unpublish")
				}
			})
		}
	}
}

func TestRetirementInternalDisablePreservesLastEnabledExit(t *testing.T) {
	database, repo, op, node, _ := reinstallGuardFixture(t)
	ctx := context.Background()
	enabled := true
	if _, err := repo.Update(ctx, node.ID, exits.UpdatePatch{Enabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	op.Reinstall, op.State, op.Phase = false, "pending", "retire_unpublish"
	op.RetirementTarget = node.Address
	if err := NewCloudRepo(database).Save(ctx, op); err != nil {
		t.Fatal(err)
	}
	if err := repo.DisableCloudRetirement(ctx, &op); !errors.Is(err, ErrExitLastEnabled) {
		t.Fatalf("last enabled exit disabled: %v", err)
	}
	current, err := repo.Get(ctx, node.ID)
	if err != nil || !current.Enabled {
		t.Fatalf("last enabled exit changed: %+v %v", current, err)
	}
}

// A crash or provider error after unpublish must retain the reservation. Retry
// may only advance deletion while the persisted exit remains disabled.
func TestRetirementFailedDeleteCannotRepublishBeforeWorkerRetry(t *testing.T) {
	database, repo, op, node, instance := reinstallGuardFixture(t)
	ctx := context.Background()
	enabled := true
	if _, err := repo.Update(ctx, node.ID, exits.UpdatePatch{Enabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Add(ctx, exits.AddParams{Name: "remaining", Address: "192.0.2.3", Port: 8443}); err != nil {
		t.Fatal(err)
	}
	op.Reinstall, op.State, op.Phase = false, "ready", "ready"
	if err := NewCloudRepo(database).Save(ctx, op); err != nil {
		t.Fatal(err)
	}
	instance.Tags = []string{"ultra", "ultra-operation-" + op.ID}
	api := &retirementGuardProvider{instance: instance, fail: true}
	provisioner := &retirementGuardProvisioner{repo: repo}
	s := &cloud.Service{Store: NewCloudRepo(database), API: api, Provisioner: provisioner}
	target := []cloud.RetirementTarget{{OperationID: op.ID, InstanceID: op.InstanceID}}
	if err := s.RetireExits(ctx, 1, target); !errors.Is(err, cloud.ErrUnavailable) {
		t.Fatal(err)
	}
	failed, err := s.Store.Get(ctx, op.ID)
	if err != nil || failed.State != "failed" || failed.Phase != "retire_delete" {
		t.Fatalf("lost checkpoint: %+v %v", failed, err)
	}
	if _, err := repo.Update(ctx, node.ID, exits.UpdatePatch{Enabled: &enabled}); !errors.Is(err, ErrExitTargetBusy) {
		t.Fatalf("republished failed retirement: %v", err)
	}
	if err := s.Action(ctx, 1, op.ID, "retry"); err != nil {
		t.Fatal(err)
	}
	api.fail = false
	for range 2 {
		if err := s.Step(ctx); err != nil {
			t.Fatal(err)
		}
	}
	current, err := repo.Get(ctx, node.ID)
	terminal, _ := s.Store.Get(ctx, op.ID)
	if err != nil || current.Enabled || terminal.State != "deleted" || api.deletes != 2 {
		t.Fatalf("unsafe retry: node=%+v op=%+v deletes=%d err=%v", current, terminal, api.deletes, err)
	}
	if _, err := repo.Update(ctx, node.ID, exits.UpdatePatch{Enabled: &enabled}); !errors.Is(err, ErrExitTargetBusy) {
		t.Fatalf("republished tombstone: %v", err)
	}
}

type retirementGuardProvider struct {
	cloud.Provider
	instance cloud.Instance
	fail     bool
	missing  bool
	deletes  int
}

func (p *retirementGuardProvider) Instances(context.Context) ([]cloud.Instance, error) {
	if p.missing {
		return nil, nil
	}
	return []cloud.Instance{p.instance}, nil
}
func (p *retirementGuardProvider) Get(ctx context.Context, _ string) (cloud.Instance, error) {
	if p.missing {
		return cloud.Instance{}, cloud.APIError{Status: 404}
	}
	instances, err := p.Instances(ctx)
	return instances[0], err
}
func (p *retirementGuardProvider) Delete(context.Context, string) error {
	p.deletes++
	if p.fail {
		return cloud.ErrUnavailable
	}
	return nil
}

type retirementGuardProvisioner struct {
	cloud.Provisioner
	repo *ExitNodeRepo
}

func (p *retirementGuardProvisioner) ValidateRetirement(ctx context.Context, op *cloud.Operation, _ cloud.Instance) error {
	return p.repo.ValidateCloudRetirementTarget(ctx, op)
}
func (p *retirementGuardProvisioner) Unpublish(ctx context.Context, op *cloud.Operation) error {
	if op.ExitID == "" {
		return nil
	}
	return p.repo.DisableCloudRetirement(ctx, op)
}
func (p *retirementGuardProvisioner) Cleanup(context.Context, *cloud.Operation) error { return nil }

func TestRetirementRejectsExistingHostAliasesBeforeCheckpoint(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, installed := range []bool{false, true} {
			t.Run(fmt.Sprintf("enabled=%t/installed=%t", enabled, installed), func(t *testing.T) {
				database, repo, op, node, instance := reinstallGuardFixture(t)
				ctx := context.Background()
				if !installed {
					if err := repo.Delete(ctx, node.ID); err != nil {
						t.Fatal(err)
					}
					op.ExitID = ""
				}
				if _, err := repo.Add(ctx, exits.AddParams{Name: "alias", Address: node.Address, Port: node.Port + 1, Enabled: &enabled}); err != nil {
					t.Fatal(err)
				}
				op.Reinstall, op.State, op.Phase = false, "ready", "ready"
				if err := NewCloudRepo(database).Save(ctx, op); err != nil {
					t.Fatal(err)
				}
				instance.Tags = []string{"ultra", "ultra-operation-" + op.ID}
				api := &retirementGuardProvider{instance: instance}
				s := &cloud.Service{Store: NewCloudRepo(database), API: api, Provisioner: &retirementGuardProvisioner{repo: repo}}
				if err := s.RetireExits(ctx, 1, []cloud.RetirementTarget{{OperationID: op.ID, InstanceID: op.InstanceID}}); !errors.Is(
					err,
					cloud.ErrConflict,
				) {
					t.Fatalf("shared host accepted: %v", err)
				}
				saved, err := s.Store.Get(ctx, op.ID)
				if err != nil || saved.Phase != "ready" || saved.RetirementTarget != "" || api.deletes != 0 {
					t.Fatalf("checkpoint/effect before validation: %+v deletes=%d err=%v", saved, api.deletes, err)
				}
			})
		}
	}
}

func TestRetirementUninstalledPaidFailureReservesHostThroughRetry(t *testing.T) {
	database, repo, op, node, instance := reinstallGuardFixture(t)
	ctx := context.Background()
	if err := repo.Delete(ctx, node.ID); err != nil {
		t.Fatal(err)
	}
	op.Reinstall, op.State, op.Phase, op.ExitID = false, "failed", "install", ""
	if err := NewCloudRepo(database).Save(ctx, op); err != nil {
		t.Fatal(err)
	}
	instance.Tags = []string{"ultra", "ultra-operation-" + op.ID}
	api := &retirementGuardProvider{instance: instance, fail: true}
	s := &cloud.Service{Store: NewCloudRepo(database), API: api, Provisioner: &retirementGuardProvisioner{repo: repo}}
	if err := s.RetireExits(ctx, 1, []cloud.RetirementTarget{{OperationID: op.ID, InstanceID: op.InstanceID}}); !errors.Is(
		err,
		cloud.ErrUnavailable,
	) {
		t.Fatal(err)
	}
	failed, err := s.Store.Get(ctx, op.ID)
	if err != nil || failed.RetirementTarget != instance.IP || failed.ExitID != "" || failed.Phase != "retire_delete" {
		t.Fatalf("missing address checkpoint: %+v %v", failed, err)
	}
	assertReserved := func() {
		t.Helper()
		for _, enabled := range []bool{true, false} {
			if _, err := repo.Add(ctx, exits.AddParams{Name: "alias", Address: instance.IP, Port: node.Port + 1, Enabled: &enabled}); !errors.Is(
				err,
				ErrExitTargetBusy,
			) {
				t.Fatalf("paid host alias accepted: %v", err)
			}
		}
	}
	assertReserved()
	if err := s.Action(ctx, 1, op.ID, "retry"); err != nil {
		t.Fatal(err)
	}
	api.fail = false
	for range 2 {
		if err := s.Step(ctx); err != nil {
			t.Fatal(err)
		}
	}
	terminal, err := s.Store.Get(ctx, op.ID)
	if err != nil || terminal.State != "deleted" || terminal.RetirementTarget != instance.IP || api.deletes != 2 {
		t.Fatalf("retry failed: %+v deletes=%d err=%v", terminal, api.deletes, err)
	}
	assertReserved()
}

func TestRetirementSavedAddressReservesUninstalledTargetInEveryPhase(t *testing.T) {
	for _, state := range []string{"pending", "failed", "deleted"} {
		for _, phase := range []string{"retire_unpublish", "retire_delete", "retire_cleanup"} {
			t.Run(state+"/"+phase, func(t *testing.T) {
				database, repo, op, node, _ := reinstallGuardFixture(t)
				ctx := context.Background()
				if err := repo.Delete(ctx, node.ID); err != nil {
					t.Fatal(err)
				}
				op.ExitID, op.Reinstall, op.State, op.Phase, op.RetirementTarget = "", false, state, phase, node.Address
				if err := NewCloudRepo(database).Save(ctx, op); err != nil {
					t.Fatal(err)
				}
				if _, err := repo.Add(ctx, exits.AddParams{Name: "alias", Address: "::ffff:" + node.Address, Port: node.Port + 1}); !errors.Is(
					err,
					ErrExitTargetBusy,
				) {
					t.Fatalf("uninstalled address escaped reservation: %v", err)
				}
			})
		}
	}
}

func TestRetirementSavedOwnRowCannotChangeIdentityOrAddress(t *testing.T) {
	for _, change := range []string{"exit-id", "address", "unexpected-own-row"} {
		t.Run(change, func(t *testing.T) {
			_, repo, op, node, _ := reinstallGuardFixture(t)
			op.RetirementTarget = node.Address
			switch change {
			case "exit-id":
				op.ExitID = "other"
			case "address":
				op.RetirementTarget = "192.0.2.9"
			case "unexpected-own-row":
				op.ExitID = ""
			}
			if err := repo.ValidateCloudRetirementTarget(context.Background(), &op); !errors.Is(err, cloud.ErrConflict) {
				t.Fatalf("changed row accepted: %v", err)
			}
		})
	}
}

func TestRetirementReplayAndWorkerRecheckHostAliasesIncludingProvider404(t *testing.T) {
	for _, phase := range []string{"retire_unpublish", "retire_delete", "retire_cleanup"} {
		for _, missing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/missing=%t", phase, missing), func(t *testing.T) {
				database, repo, op, node, instance := reinstallGuardFixture(t)
				ctx := context.Background()
				if _, err := repo.Add(ctx, exits.AddParams{Name: "alias", Address: node.Address, Port: node.Port + 1}); err != nil {
					t.Fatal(err)
				}
				op.Reinstall, op.State, op.Phase, op.RetirementTarget = false, "pending", phase, node.Address
				if err := NewCloudRepo(database).Save(ctx, op); err != nil {
					t.Fatal(err)
				}
				instance.Tags = []string{"ultra", "ultra-operation-" + op.ID}
				api := &retirementGuardProvider{instance: instance, missing: missing}
				s := &cloud.Service{Store: NewCloudRepo(database), API: api, Provisioner: &retirementGuardProvisioner{repo: repo}}
				if err := s.RetireExits(ctx, 1, []cloud.RetirementTarget{{OperationID: op.ID, InstanceID: op.InstanceID}}); !errors.Is(
					err,
					cloud.ErrConflict,
				) {
					t.Fatalf("replay ignored alias: %v", err)
				}
				if err := s.Step(ctx); !errors.Is(err, cloud.ErrConflict) {
					t.Fatalf("worker ignored alias: %v", err)
				}
				saved, err := s.Store.Get(ctx, op.ID)
				if err != nil || saved.Phase != phase || saved.State != "failed" || api.deletes != 0 {
					t.Fatalf("alias caused effects: %+v deletes=%d err=%v", saved, api.deletes, err)
				}
			})
		}
	}
}
