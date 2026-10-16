package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestManagedTLSUpgradeRejectsBeforeOperationIO(t *testing.T) {
	for _, mode := range []struct {
		name        string
		retryFailed bool
		forwardOnly bool
	}{
		{name: "ordinary"},
		{name: "retry", retryFailed: true},
		{name: "forward-only", forwardOnly: true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			root := t.TempDir()
			directory := filepath.Join(root, "operation")
			// Deliberately absent release/runtime inputs: the managed TLS guard
			// must reject before plan freezing, release staging or remote work.
			plan := &installplan.InstallPlan{
				Features: installplan.FeatureConfig{MainExitDomain: "tunnel.example.com"},
			}
			before, err := json.Marshal(plan)
			if err != nil {
				t.Fatal(err)
			}
			err = ansibleUpgrade(context.Background(), plan,
				filepath.Join(root, "absent-release"), directory,
				filepath.Join(root, "absent-python"), filepath.Join(root, "absent-ansible"),
				mode.retryFailed, mode.forwardOnly)
			const want = "upgrade_managed_tunnel_preservation_envelope_required"
			if err == nil || err.Error() != want {
				t.Fatalf("upgrade error = %v, want %q", err, want)
			}
			after, err := json.Marshal(plan)
			if err != nil || string(after) != string(before) {
				t.Fatal("rejected upgrade mutated the caller's plan")
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 0 {
				t.Fatalf("rejected upgrade created operation inputs: %v, %v", entries, err)
			}
		})
	}
}

func TestManagedTLSCompensationEvidenceNeverAuthorizesOrdinaryInspection(t *testing.T) {
	requests := map[string]any{
		"exit_fixture": runtimeProbeInput{
			Request: runtimeHostRequest{Role: "exit", Features: installplan.FeatureConfig{MainExitDomain: "tunnel.example.com"}},
		},
	}
	values := map[string]any{
		"verified": true,
		"hosts":    map[string]any{"exit_fixture": runtimeProbeResult{Verified: true, ManagedTLSRestorable: true}},
	}
	if err := validateUpgradeRuntimeEvidence(values, requests); err == nil {
		t.Fatal("ordinary inspection accepted checkpoint-only evidence")
	}
	if err := validateUpgradeRuntimeEvidence(values, requests, true); err != nil {
		t.Fatalf("compensation evidence: %v", err)
	}
}

func TestManagedTLSCompensationRequiresFailedActivationGeneration(t *testing.T) {
	for _, generation := range []int{1, 2, -1} {
		directory := t.TempDir()
		plan := &installplan.InstallPlan{Features: installplan.FeatureConfig{MainExitDomain: "tunnel.example.com"}}
		err := inspectUpgradeRuntimeForPurpose(
			context.Background(),
			plan,
			upgradeInspection{},
			nil,
			nil,
			directory,
			"/absent/python",
			"/absent/ansible",
			generation,
		)
		if err == nil {
			t.Fatal("compensation accepted without failed activation")
		}
		entries, readErr := os.ReadDir(directory)
		if readErr != nil || len(entries) != 0 {
			t.Fatalf("unbound compensation performed operation IO: %v", readErr)
		}
	}
}
