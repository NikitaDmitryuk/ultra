package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

func TestRecoveryPreparationRetryRequiresExplicitControlAndEligiblePhase(t *testing.T) {
	for _, phase := range []string{"origins_sealed", "recovery_reconciled", "readiness_verified"} {
		if recoveryPreparationRetryAuthorized(phase, []string{"--retry-failed"}) {
			t.Fatal("ambiguous phase retry authorized")
		}
	}
	for _, args := range [][]string{nil, {"--retry-failed=false"}, {"--retry-failed", "--retry-failed"}, {"--retry-failed=true", "--retry-failed=false"}} {
		if recoveryPreparationRetryAuthorized("tools_staged", args) {
			t.Fatal("implicit or conflicting retry authorized")
		}
	}
	for _, phase := range []string{"tools_staged", "monitor_initialized"} {
		if !recoveryPreparationRetryAuthorized(phase, []string{"operator-upgrade", "--retry-failed"}) {
			t.Fatal("explicit normal-job retry rejected")
		}
	}
}

func TestRecoveryPreparationNormalTaskFailureRetainsExactJobAndAllowsExplicitRetry(t *testing.T) {
	configuredAnsible := os.Getenv("ULTRA_TEST_ANSIBLE_PLAYBOOK")
	if configuredAnsible == "" {
		t.Skip("set ULTRA_TEST_ANSIBLE_PLAYBOOK to run the pinned Ansible integration test")
	}
	ansible, err := exec.LookPath(configuredAnsible)
	if err != nil {
		t.Skip("configured Ansible unavailable")
	}
	root := t.TempDir()
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	r := recoveryPreparationRequest{Protocol: "ultra-recovery-preparation-request-v1", StateDirectory: root}
	directory := filepath.Join(root, "ansible-tools_staged")
	inventory := map[string]any{
		"all": map[string]any{
			"children": map[string]any{
				"bridge": map[string]any{
					"hosts": map[string]any{
						"bridge": map[string]any{"ansible_connection": "local", "ansible_python_interpreter": "/usr/bin/python3"},
					},
				},
			},
		},
	}
	// Fail at the first read-only path assertion, before any system path task.
	variables := map[string]any{
		"ultra_lock_directory":               root,
		"ultra_preparation_snapshot":         "invalid",
		"ultra_preparation_remote_directory": "invalid",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	receipt, err := deployansible.RunLocal(
		ctx,
		"stage-recovery-preparation",
		inventory,
		variables,
		directory,
		ansibleControllerPython,
		ansible,
	)
	if err == nil || receipt.State != "failed" {
		t.Fatalf("expected normal task failure: %+v %v", receipt, err)
	}
	if fence, e := deployansible.InspectExecutionFence(); e != nil || fence != nil {
		raw, _ := os.ReadFile(filepath.Join(directory, "receipt.json"))
		terminal, _ := os.ReadFile(filepath.Join(directory, "ansible-terminal.json"))
		t.Fatalf("trusted terminal task failure not closed: %+v %v receipt=%s terminal=%s", fence, e, raw, terminal)
	}
	if err = recordRecoveryPreparationRetry(r, "tools_staged", 123); err != nil {
		t.Fatal(err)
	}
	locked, release, e := deployansible.WithOperationLock(ctx, root)
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	_, err = deployansible.RunLocalRetryFailed(
		locked,
		"stage-recovery-preparation",
		inventory,
		variables,
		directory,
		ansibleControllerPython,
		ansible,
	)
	if err == nil {
		t.Fatal("invalid input unexpectedly succeeded")
	}
	raw, e := os.ReadFile(filepath.Join(directory, "job.json"))
	if e != nil {
		t.Fatal(e)
	}
	var metadata struct {
		Attempt int `json:"attempt"`
	}
	if json.Unmarshal(raw, &metadata) != nil || metadata.Attempt != 2 {
		t.Fatalf("exact normal-failure job did not advance attempt: %s retry_error=%v", raw, err)
	}
	if fence, e := deployansible.InspectExecutionFence(); e != nil || fence != nil {
		t.Fatalf("retry cleanup unproven: %+v %v", fence, e)
	}
	if _, e = os.Stat(preparationPhasePath(r, "tools_staged", ".retry-0")); e != nil {
		t.Fatal("immutable retry descriptor missing", e)
	}
}
