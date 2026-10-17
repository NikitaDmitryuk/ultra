package db

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/google/uuid"
)

func reinstallGuardFixture(t *testing.T) (*DB, *ExitNodeRepo, cloud.Operation, exits.Node, cloud.Instance) {
	t.Helper()
	database := openTestDB(t)
	repo := NewExitNodeRepo(database)
	disabled := false
	node, err := repo.Add(
		context.Background(),
		exits.AddParams{
			ID:                   uuid.NewString(),
			Name:                 "staged",
			Address:              "192.0.2.2",
			Port:                 8443,
			Enabled:              &disabled,
			PinnedPeerCertSHA256: strings.Repeat("ab", 32),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	op := cloud.Operation{
		ID:             node.ID,
		ExitID:         node.ID,
		InstanceID:     "instance-fixture",
		State:          "pending",
		Phase:          "install",
		Reinstall:      true,
		InstallAttempt: 1,
	}
	saveGuardOperation(t, database, op)
	return database, repo, op, node, cloud.Instance{ID: op.InstanceID, IP: node.Address}
}
func saveGuardOperation(t *testing.T, database *DB, op cloud.Operation) {
	t.Helper()
	ctx := context.Background()
	if err := NewCloudRepo(database).SaveOffer(ctx, cloud.Offer{ID: op.ID, Actor: 1, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(op)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `INSERT INTO cloud_operations(id,state,body) VALUES($1,$2,$3)`, op.ID, op.State, body); err != nil {
		t.Fatal(err)
	}
}

func TestReinstallGuardRejectsAddressAliasesRegardlessOfActivation(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(map[bool]string{true: "enabled", false: "disabled"}[enabled], func(t *testing.T) {
			_, repo, op, node, instance := reinstallGuardFixture(t)
			_, err := repo.Add(
				context.Background(),
				exits.AddParams{Name: "alias", Address: node.Address, Port: node.Port + 1, Enabled: &enabled},
			)
			if err != nil {
				t.Fatal(err)
			}
			release, err := repo.GuardCloudReinstall(context.Background(), &op, node, instance)
			if release != nil {
				release()
			}
			if !errors.Is(err, cloud.ErrConflict) {
				t.Fatalf("shared host accepted: %v", err)
			}
		})
	}
}
func TestReinstallGuardRejectsProviderAliasAndStaleBinding(t *testing.T) {
	for _, kind := range []string{"instance", "operation", "node"} {
		t.Run(kind, func(t *testing.T) {
			database, repo, op, node, instance := reinstallGuardFixture(t)
			switch kind {
			case "instance":
				alias := op
				alias.ID = uuid.NewString()
				alias.ExitID = ""
				alias.State = "deleted"
				saveGuardOperation(t, database, alias)
			case "operation":
				op.InstallAttempt++
			case "node":
				node.Port++
			}
			release, err := repo.GuardCloudReinstall(context.Background(), &op, node, instance)
			if release != nil {
				release()
			}
			if !errors.Is(err, cloud.ErrConflict) {
				t.Fatalf("unbound %s accepted: %v", kind, err)
			}
		})
	}
}
func TestReinstallGuardExcludesConcurrentClaimsWithoutBlockingOtherHosts(t *testing.T) {
	_, repo, op, node, instance := reinstallGuardFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	release, err := repo.GuardCloudReinstall(ctx, &op, node, instance)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	enabled := true
	disabled := false
	unrelated, err := repo.Add(ctx, exits.AddParams{Name: "unrelated", Address: "192.0.2.3", Port: 8443, Enabled: &disabled})
	if err != nil {
		t.Fatal("unrelated host blocked", err)
	}
	calls := []func() error{
		func() error {
			_, err := repo.Add(ctx, exits.AddParams{Name: "new-alias", Address: node.Address, Port: 9443, Enabled: &enabled})
			return err
		},
		func() error { _, err := repo.Update(ctx, node.ID, exits.UpdatePatch{Enabled: &enabled}); return err },
		func() error {
			_, err := repo.Update(ctx, unrelated.ID, exits.UpdatePatch{Address: &node.Address})
			return err
		},
		func() error { return repo.Delete(ctx, node.ID) },
		func() error {
			return repo.mergeBootstrapEntry(
				ctx,
				exits.BootstrapEntry{Name: "import", Address: node.Address, Port: node.Port, Enabled: &enabled},
			)
		},
	}
	results := make(chan error, len(calls))
	for _, call := range calls {
		go func(call func() error) { results <- call() }(call)
	}
	for range calls {
		if err := <-results; !errors.Is(err, ErrExitTargetBusy) {
			t.Fatalf("concurrent claim escaped: %v", err)
		}
	}
	if _, err := repo.Update(ctx, unrelated.ID, exits.UpdatePatch{Enabled: &enabled}); err != nil {
		t.Fatal("unrelated activation blocked", err)
	}
	release()
	if err := repo.ClearCloudReinstall(ctx, &op); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Update(ctx, node.ID, exits.UpdatePatch{Enabled: &enabled}); err != nil {
		t.Fatal("target remained locked", err)
	}
}

func TestExitTargetLockNormalizesIP(t *testing.T) {
	if exitTargetLock("2001:db8::1") != exitTargetLock("2001:0db8:0:0:0:0:0:1") {
		t.Fatal("equivalent addresses use different guards")
	}
	if exitTargetLock("192.0.2.1") == exitTargetLock("192.0.2.2") {
		t.Fatal("unrelated targets share guard")
	}
}

func TestReinstallReservationSurvivesSessionLossAndRequiresBoundRelease(t *testing.T) {
	database, repo, op, node, instance := reinstallGuardFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	release, err := repo.GuardCloudReinstall(ctx, &op, node, instance)
	if err != nil {
		t.Fatal(err)
	}
	stale := op
	jobID := uuid.NewString()
	if err := repo.ReserveCloudReinstall(ctx, &op, jobID, node.Address); err != nil {
		release()
		t.Fatal(err)
	}
	release() // Simulate installer timeout/disconnect: the worker can still run.
	restarted := NewExitNodeRepo(database)
	saved, err := NewCloudRepo(database).Get(ctx, op.ID)
	if err != nil || saved.ReinstallJobID != jobID || saved.ReinstallTarget != node.Address {
		t.Fatal("reservation not durable", err)
	}
	enabled := true
	if _, err := restarted.Add(ctx, exits.AddParams{Name: "racing-alias", Address: node.Address, Port: 9443, Enabled: &enabled}); !errors.Is(
		err,
		ErrExitTargetBusy,
	) {
		t.Fatalf("create escaped caller loss: %v", err)
	}
	if _, err := restarted.Update(ctx, node.ID, exits.UpdatePatch{Enabled: &enabled}); !errors.Is(err, ErrExitTargetBusy) {
		t.Fatalf("activation escaped caller loss: %v", err)
	}
	if err := restarted.Delete(ctx, node.ID); !errors.Is(err, ErrExitTargetBusy) {
		t.Fatalf("delete escaped caller loss: %v", err)
	}
	if err := NewCloudRepo(database).Save(ctx, stale); !errors.Is(err, cloud.ErrConflict) {
		t.Fatalf("stale writer erased reservation: %v", err)
	}
	other := op
	other.ReinstallJobID = uuid.NewString()
	if err := restarted.ClearCloudReinstall(ctx, &other); !errors.Is(err, cloud.ErrConflict) {
		t.Fatalf("different worker released reservation: %v", err)
	}
	if _, err := restarted.Add(ctx, exits.AddParams{Name: "other-host", Address: "192.0.2.99", Port: 8443, Enabled: &enabled}); err != nil {
		t.Fatal("other host blocked after caller loss", err)
	}
	// Production only reaches this release after ConfigurationTerminal returns true.
	if err := restarted.ClearCloudReinstall(ctx, &op); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Update(ctx, node.ID, exits.UpdatePatch{Enabled: &enabled}); err != nil {
		t.Fatal("terminal release did not reopen target", err)
	}
}

func TestPreflightReservationSurvivesSessionLossBeforeJobBinding(t *testing.T) {
	database, repo, op, node, instance := reinstallGuardFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	release, err := repo.GuardCloudReinstall(ctx, &op, node, instance)
	if err != nil {
		t.Fatal(err)
	}
	release() // Lose the validating session before SSH preflight and job binding.
	saved, err := NewCloudRepo(database).Get(ctx, op.ID)
	if err != nil || saved.ReinstallTarget != node.Address || saved.ReinstallJobID != "" {
		t.Fatal("preflight target was not atomically reserved", err)
	}
	enabled, disabled := true, false
	unrelated, err := repo.Add(ctx, exits.AddParams{Name: "other", Address: "192.0.2.3", Port: 8443, Enabled: &disabled})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Add(ctx, exits.AddParams{Name: "alias", Address: node.Address, Port: 9443, Enabled: &enabled}); !errors.Is(
		err,
		ErrExitTargetBusy,
	) {
		t.Fatalf("alias claimed preflight target: %v", err)
	}
	if _, err := repo.Update(ctx, node.ID, exits.UpdatePatch{Enabled: &enabled}); !errors.Is(err, ErrExitTargetBusy) {
		t.Fatalf("activation claimed preflight target: %v", err)
	}
	if _, err := repo.Update(ctx, unrelated.ID, exits.UpdatePatch{Address: &node.Address}); !errors.Is(err, ErrExitTargetBusy) {
		t.Fatalf("address change claimed preflight target: %v", err)
	}
	// A restarted attempt revalidates the same saved generation, then binds its job.
	release, err = NewExitNodeRepo(database).GuardCloudReinstall(ctx, &saved, node, instance)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	beforeBinding := saved
	jobID := uuid.NewString()
	if err := repo.ReserveCloudReinstall(ctx, &saved, jobID, node.Address); err != nil {
		t.Fatal(err)
	}
	if saved.InstallAttempt != op.InstallAttempt || saved.ReinstallJobID != jobID {
		t.Fatal("resume changed attempt identity")
	}
	if err := repo.ClearCloudReinstall(ctx, &beforeBinding); !errors.Is(err, cloud.ErrConflict) {
		t.Fatalf("unbound stale owner cleared a bound job: %v", err)
	}
}

func TestPreflightReservationCannotBeResurrectedAfterClear(t *testing.T) {
	_, repo, op, node, instance := reinstallGuardFixture(t)
	ctx := context.Background()
	release, err := repo.GuardCloudReinstall(ctx, &op, node, instance)
	if err != nil {
		t.Fatal(err)
	}
	release()
	stale := op
	// No job is bound, so cancel/delete may clear via a CAS before submission.
	if err := repo.ClearCloudReinstall(ctx, &op); err != nil {
		t.Fatal(err)
	}
	enabled := true
	if _, err := repo.Add(ctx, exits.AddParams{Name: "new-owner", Address: node.Address, Port: 9443, Enabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	if err := repo.ReserveCloudReinstall(ctx, &stale, uuid.NewString(), node.Address); !errors.Is(err, cloud.ErrConflict) {
		t.Fatalf("stale preflight resurrected a claimed target: %v", err)
	}
}
