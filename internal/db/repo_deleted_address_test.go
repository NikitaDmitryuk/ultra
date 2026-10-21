package db

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/google/uuid"
)

func TestOrdinaryDeletedAddressReusedWithoutResurrectingIdentity(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "saved_address", true: "legacy"}[legacy], func(t *testing.T) {
			database, repo, old, node, _ := reinstallGuardFixture(t)
			ctx := context.Background()
			old.Reinstall, old.State, old.Phase = false, "deleted", "cleanup"
			if !legacy {
				old.RetirementTarget = node.Address
			}
			if err := NewCloudRepo(database).Save(ctx, old); err != nil {
				t.Fatal(err)
			}
			disabled, enabled := false, true
			newID := uuid.NewString()
			if _, err := repo.Add(ctx, exits.AddParams{ID: newID, Name: "reused", Address: node.Address, Port: node.Port, Enabled: &disabled}); err != nil {
				t.Fatalf("new identity install blocked: %v", err)
			}
			if _, err := repo.Update(ctx, newID, exits.UpdatePatch{Enabled: &enabled}); err != nil {
				t.Fatalf("new identity publish blocked: %v", err)
			}
			anotherAddress := "192.0.2.99"
			for _, patch := range []exits.UpdatePatch{{Enabled: &enabled}, {Address: &anotherAddress}} {
				if _, err := repo.Update(ctx, node.ID, patch); !errors.Is(err, ErrExitTargetBusy) {
					t.Fatalf("historical identity resurrected: %v", err)
				}
			}
			if err := repo.Delete(ctx, node.ID); !errors.Is(err, ErrExitTargetBusy) {
				t.Fatalf("historical identity deleted: %v", err)
			}
			// A stale bootstrap entry must not merge the disabled historical row back in.
			if err := repo.withMutation(ctx, func(r *ExitNodeRepo) error {
				return r.mergeBootstrapEntry(ctx, exits.BootstrapEntry{Name: "old", Address: anotherAddress, Port: node.Port, TunnelUUID: node.TunnelUUID})
			}); !errors.Is(err, ErrExitTargetBusy) {
				t.Fatalf("bootstrap resurrected historical identity: %v", err)
			}
			// Tombstone identity remains protected even if the historical row disappeared.
			if _, err := database.Pool.Exec(ctx, `DELETE FROM exit_nodes WHERE id=$1`, node.ID); err != nil {
				t.Fatal(err)
			}
			for _, oldID := range []string{node.ID, strings.ToUpper(node.ID), "urn:uuid:" + node.ID} {
				if _, err := repo.Add(ctx, exits.AddParams{ID: oldID, Name: "resurrect", Address: anotherAddress, Port: node.Port}); !errors.Is(
					err,
					ErrExitTargetBusy,
				) {
					t.Fatalf("old operation ID reused: %v", err)
				}
			}
		})
	}
}

func TestOrdinaryDeleteHistoricalAliasRequiresCompletedDistinctIdentity(t *testing.T) {
	for _, change := range []string{"saved_address", "legacy", "pending", "failed", "explicit_retirement", "enabled", "unknown", "different_exit", "same_instance", "missing_instance", "changed_address", "reinstall_reserved", "explicit_new_retirement"} {
		t.Run(change, func(t *testing.T) {
			database, repo, old, node, _ := reinstallGuardFixture(t)
			ctx := context.Background()
			old.Reinstall, old.State, old.Phase = false, "deleted", "cleanup"
			old.RetirementTarget = node.Address
			current := cloud.Operation{
				ID:               uuid.NewString(),
				InstanceID:       "new-instance",
				State:            "pending",
				Phase:            "delete",
				RetirementTarget: node.Address,
			}
			switch change {
			case "legacy":
				old.RetirementTarget = ""
				old.ExitID = ""
			case "pending", "failed":
				old.State = change
			case "explicit_retirement":
				old.Phase = "retire_cleanup"
			case "enabled":
				if _, err := database.Pool.Exec(ctx, `UPDATE exit_nodes SET enabled=true WHERE id=$1`, node.ID); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				if _, err := database.Pool.Exec(ctx, `DELETE FROM cloud_operations WHERE id=$1`, old.ID); err != nil {
					t.Fatal(err)
				}
			case "different_exit":
				old.ExitID = uuid.NewString()
			case "same_instance":
				current.InstanceID = old.InstanceID
			case "missing_instance":
				old.InstanceID = ""
			case "changed_address":
				old.RetirementTarget = "192.0.2.99"
			case "reinstall_reserved":
				old.ReinstallTarget = node.Address
			case "explicit_new_retirement":
				current.Phase = "retire_delete"
			}
			if change != "unknown" {
				body, err := json.Marshal(old)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := database.Pool.Exec(ctx, `UPDATE cloud_operations SET state=$2,body=$3 WHERE id=$1`, old.ID, old.State, body); err != nil {
					t.Fatal(err)
				}
			}
			var err error
			if change == "explicit_new_retirement" {
				err = repo.ValidateCloudRetirementTarget(ctx, &current)
			} else {
				err = repo.ValidateCloudDeleteTarget(ctx, &current)
			}
			if change == "saved_address" || change == "legacy" {
				if err != nil {
					t.Fatalf("completed historical alias blocked new paid VPS deletion: %v", err)
				}
			} else if !errors.Is(err, cloud.ErrConflict) {
				t.Fatalf("unsafe alias accepted: %v", err)
			}
		})
	}
}
