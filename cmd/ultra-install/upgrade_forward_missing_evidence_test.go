package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// An operator plan describes desired hosts; it cannot replace the exact fleet
// dispatched by a historical activation, even when that activation left no
// request at all. Request-bound job/receipt bytes are independently required.
func TestForwardOldOperationMissingActivationEvidenceFailsClosed(t *testing.T) {
	for _, missing := range []string{"request.json", "job.json", "receipt.json", "activate"} {
		t.Run(missing, func(t *testing.T) {
			proof, root, directory := forwardFixture(t)
			path := filepath.Join(directory, "activate", missing)
			if missing == "activate" {
				path = filepath.Join(directory, missing)
			}
			if err := os.RemoveAll(path); err != nil {
				t.Fatal(err)
			}
			journal, err := os.ReadFile(proof.Path)
			if err != nil {
				t.Fatal(err)
			}
			old, err := discoverForwardOldOperation(proof, root)
			if err == nil || err.Error() != "upgrade_forward_old_operation_unverified" || old.ID != "" || old.Inventory != nil {
				t.Fatalf("missing evidence authorized a fleet: %+v %v", old, err)
			}
			if _, err = os.Lstat(path); !os.IsNotExist(err) {
				t.Fatalf("missing evidence was synthesized: %v", err)
			}
			after, err := os.ReadFile(proof.Path)
			if err != nil || string(after) != string(journal) {
				t.Fatalf("original journal changed: %v", err)
			}
		})
	}
}

// A released bootstrap reservation is not proof that a different predecessor
// drained. Reject it before attaching leases, running census, or superseding.
func TestForwardHandoffForeignReleasedLifecycleDoesNotDispatch(t *testing.T) {
	proof, old, root, directory, deps, events, held := forwardReplayFixture(t)
	writeForwardJSON(t, filepath.Join(root, "lifecycle.json"), map[string]any{
		"id": lifecycleID("unrelated-bootstrap"), "phase": "released",
	})
	_, release, err := forwardUpgradeHandoff(context.Background(), proof, old, root, directory, "/python", "/ansible", deps)
	if err == nil || err.Error() != "upgrade_forward_lifecycle_not_owned" || release != nil || *held || len(*events) != 0 {
		t.Fatalf("unowned released lifecycle dispatched: err=%v held=%v events=%v", err, *held, *events)
	}
	if _, err = os.Lstat(filepath.Join(directory, "forward-handoff.json")); !os.IsNotExist(err) {
		t.Fatalf("unowned lifecycle published a handoff: %v", err)
	}
}
