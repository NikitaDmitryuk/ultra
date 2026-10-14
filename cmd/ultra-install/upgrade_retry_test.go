package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFailedUpgradeRetryPreservesHistoryAndResetsRollbackCache(t *testing.T) {
	directory := t.TempDir()
	for step, state := range map[string]string{"activate": "succeeded", "rollback": "succeeded"} {
		path := filepath.Join(directory, step)
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		job := map[string]any{"operation": step, "request_sha256": "fixture", "binary_sha256": "fixture"}
		receipt := map[string]any{"state": state, "request_sha256": "fixture", "binary_sha256": "fixture", "attempt": 1}
		for name, value := range map[string]map[string]any{"job.json": job, "receipt.json": receipt} {
			data, _ := json.Marshal(value)
			if err := os.WriteFile(filepath.Join(path, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := resetFailedUpgradeAttempt(directory); err != nil {
		t.Fatal(err)
	}
	// Repeating --retry-failed after receipt removal resumes the prepared attempt.
	if err := resetFailedUpgradeAttempt(directory); err != nil {
		t.Fatal(err)
	}
	// Simulate the earlier crash boundary: job 2 with the old receipt 1 still active.
	oldReceipt, err := os.ReadFile(filepath.Join(directory, "history", "activate-attempt-1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, "activate", "receipt.json"), oldReceipt, 0600); err != nil {
		t.Fatal(err)
	}
	if err = resetFailedUpgradeAttempt(directory); err != nil {
		t.Fatal(err)
	}
	for _, step := range []string{"activate", "rollback"} {
		if _, err := os.Stat(filepath.Join(directory, step, "receipt.json")); (step == "activate" && !os.IsNotExist(err)) || (step != "activate" && err != nil) {
			t.Fatal("activation cache not cleared or dependent history removed")
		}
		if _, err := os.Stat(filepath.Join(directory, "history", step+"-attempt-1.json")); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(directory, step, "job.json"))
		if err != nil {
			t.Fatal(err)
		}
		var job map[string]any
		expectedAttempt := any(nil)
		if step == "activate" {
			expectedAttempt = float64(2)
		}
		if json.Unmarshal(raw, &job) != nil || job["attempt"] != expectedAttempt || job["request_sha256"] != "fixture" {
			t.Fatal("attempt counter or frozen hash changed incorrectly")
		}
	}
}
func TestUpgradeRetryRejectsCommittedOrUnfailedOperations(t *testing.T) {
	if resetFailedUpgradeAttempt(t.TempDir()) == nil {
		t.Fatal("no failed operation accepted")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "commit")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "receipt.json"), []byte(`{"state":"succeeded"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if resetFailedUpgradeAttempt(directory) == nil {
		t.Fatal("committed operation repeated")
	}
}
func TestAutomationStatusNeverPublishesPrivateInspection(t *testing.T) {
	result := publicAutomationStatus(map[string]any{"ready": true, "version": "v2.4.7", "identity": "private", "nodes": []string{"private"}, "pins": "private", "auto_policy": "private"})
	if len(result) != 2 || result["ready"] != true || result["version"] != "v2.4.7" {
		t.Fatal("public status projection leaked or dropped fields")
	}
}

func TestUpgradeRetryGeneratesFreshTimestampDependentStages(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python unavailable")
	}
	root := t.TempDir()
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, release, err := deployansible.WithOperationLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	executable := filepath.Join(root, "ansible")
	source := "#!" + python + "\n" + `import json,pathlib,sys
job=pathlib.Path(sys.argv[-1][1:]).parent
count=job/'calls'
n=int(count.read_text())+1 if count.exists() else 1
count.write_text(str(n))
result=job/'result.json'
result.write_text(json.dumps({'verified':True,'activated_at':n*100}))
result.chmod(0o600)
`
	if err = os.WriteFile(executable, []byte(source), 0700); err != nil {
		t.Fatal(err)
	}
	inventory := map[string]any{}
	variables := map[string]any{"ultra_lock_directory": root, "ultra_upgrade_observed_at": 1}
	activation, err := deployansible.RunLocal(ctx, "upgrade", inventory, variables, filepath.Join(root, "activate"), python, executable)
	if err != nil {
		t.Fatal(err)
	}
	variables["ultra_upgrade_observed_at"] = activation.Result.Values["activated_at"]
	for _, stage := range []string{"publish", "rollback"} {
		operation := stage
		if stage == "publish" {
			operation = "publish-release"
		}
		if _, err = deployansible.RunLocal(ctx, operation, inventory, variables, upgradeDependentStageDirectory(root, stage, 1), python, executable); err != nil {
			t.Fatal(err)
		}
	}
	originalRequest, err := os.ReadFile(filepath.Join(root, "publish", "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = resetFailedUpgradeAttempt(root); err != nil {
		t.Fatal(err)
	}
	generation, err := upgradeActivationGeneration(root, false)
	if err != nil || generation != 2 {
		t.Fatalf("generation: %d %v", generation, err)
	}
	variables["ultra_upgrade_observed_at"] = 1
	activation, err = deployansible.RunLocal(ctx, "upgrade", inventory, variables, filepath.Join(root, "activate"), python, executable)
	if err != nil {
		t.Fatal(err)
	}
	variables["ultra_upgrade_observed_at"] = activation.Result.Values["activated_at"]
	// The previous layout reproduces the confirmed immutable-input failure.
	if _, err = deployansible.RunLocal(ctx, "publish-release", inventory, variables, filepath.Join(root, "publish"), python, executable); err == nil || !strings.Contains(err.Error(), "local operation inputs changed") {
		t.Fatal("old timestamp request unexpectedly accepted")
	}
	for _, stage := range []string{"publish", "commit"} {
		operation := "publish-release"
		if stage == "commit" {
			operation = "commit-release"
		}
		path := upgradeDependentStageDirectory(root, stage, generation)
		for i := 0; i < 2; i++ {
			if _, err = deployansible.RunLocal(ctx, operation, inventory, variables, path, python, executable); err != nil {
				t.Fatal(err)
			}
		}
		calls, _ := os.ReadFile(filepath.Join(path, "calls"))
		if string(calls) != "1" {
			t.Fatal("same generation replayed a successful stage")
		}
		variables["ultra_upgrade_observed_at"] = 300
		if _, err = deployansible.RunLocal(ctx, operation, inventory, variables, path, python, executable); err == nil {
			t.Fatal("same-generation identity changed")
		}
		variables["ultra_upgrade_observed_at"] = activation.Result.Values["activated_at"]
	}
	after, err := os.ReadFile(filepath.Join(root, "publish", "request.json"))
	if err != nil || !bytes.Equal(originalRequest, after) {
		t.Fatal("historical publish request changed")
	}
	if _, err = os.Stat(filepath.Join(root, "publish", "receipt.json")); err != nil {
		t.Fatal("historical publish receipt removed")
	}
}
