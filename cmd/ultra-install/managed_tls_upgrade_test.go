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
			const want = "managed tunnel TLS upgrade is not supported yet; preserve the existing installation and do not bypass this guard with bootstrap"
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
