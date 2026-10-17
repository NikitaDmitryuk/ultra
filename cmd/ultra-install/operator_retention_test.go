package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func retentionOperationFixture(t *testing.T, root, version string) string {
	t.Helper()
	directory := filepath.Join(root, "operation-"+version)
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(path string, value any) {
		raw, _ := json.Marshal(value)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(directory, "inventory.frozen.json"), map[string]any{"all": map[string]any{}})
	write(filepath.Join(directory, "execution-mode.json"), map[string]any{"schema_version": 1, "target": "fixture"})
	if err := freezeOperatorPlan(directory, &installplan.InstallPlan{}, "/private/release"); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"inspect", "verify-failed", "activate", "publish", "commit"} {
		job := filepath.Join(directory, stage)
		if err := os.MkdirAll(filepath.Join(job, "bundle"), 0700); err != nil {
			t.Fatal(err)
		}
		write(
			filepath.Join(job, "request.json"),
			map[string]any{
				"variables": map[string]any{
					"ultra_release_version":         version,
					"ultra_release_manifest_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
					"ultra_release_manifest": map[string]any{
						"version":       version,
						"source_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					},
				},
			},
		)
		hash, _ := sourceSHA(filepath.Join(job, "request.json"))
		write(
			filepath.Join(job, "job.json"),
			map[string]any{
				"schema_version": 1,
				"request_sha256": hash,
				"operation":      map[string]string{"activate": "upgrade", "publish": "publish-release", "commit": "commit-release", "inspect": "inspect", "verify-failed": "verify-failed"}[stage],
			},
		)
		state := "succeeded"
		if stage == "verify-failed" {
			state = "failed"
		}
		write(filepath.Join(job, "receipt.json"), map[string]any{"state": state, "request_sha256": hash})
		if err := os.WriteFile(filepath.Join(job, "bundle", "controller.py"), []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
		if stage == "verify-failed" {
			cache := filepath.Join(job, "bundle", "__pycache__")
			if err := os.Mkdir(cache, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(cache, "controller.cpython-312.pyc"), []byte("cache"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		inventory, err := operatorPayloadInventory(filepath.Join(job, "bundle"))
		if err != nil {
			t.Fatal(err)
		}
		if stage == "verify-failed" {
			cache := filepath.Join(job, "bundle", "__pycache__", "controller.cpython-312.pyc")
			hash, _ := sourceSHA(cache)
			inventory["__pycache__"] = []any{"directory", 0700}
			inventory["__pycache__/controller.cpython-312.pyc"] = []any{"file", hash, 0600}
		}
		write(
			filepath.Join(job, "bundle.retention.json"),
			map[string]any{
				"schema":    1,
				"path":      filepath.Join(job, "bundle"),
				"identity":  map[string]string{"request_sha256": hash},
				"inventory": inventory,
			},
		)
	}
	if err := os.Mkdir(filepath.Join(directory, "recovery-bundle"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "recovery-bundle", "recovery.py"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	return directory
}
func TestOperatorCompletionBoundsAllPayloadsAndReplaysAfterPartialGC(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	versions := []string{"v1.0.0", "v2.0.0", "v3.0.0", "v4.0.0"}
	manifests := []*automationRelease{}
	directories := []string{}
	for _, version := range versions {
		manifest := &automationRelease{Version: version, SourceCommit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
		directory := retentionOperationFixture(t, root, version)
		if err := sealCompletedOperatorOperation(directory, "upgrade", manifest, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); err != nil {
			t.Fatal(err)
		}
		manifests = append(manifests, manifest)
		directories = append(directories, directory)
	}
	// Actual recursive-delete crash: retain the tree root with only a subset.
	partial := filepath.Join(directories[0], "verify-failed", "bundle")
	expected, err := operatorPayloadContents(partial)
	if err != nil {
		t.Fatal(err)
	}
	if !operatorDeletionPermitted(root, partial, expected, expected) {
		t.Fatal("deletion intent not durable")
	}
	if err := os.Remove(filepath.Join(partial, "controller.py")); err != nil {
		t.Fatal(err)
	}
	// Crash between deletions cannot erase the completion metadata/cache result.
	if err := os.RemoveAll(filepath.Join(directories[0], "inspect", "bundle")); err != nil {
		t.Fatal(err)
	}
	if err := collectCompletedOperatorArtifacts(root, manifests[2], manifests[3]); err != nil {
		t.Fatal(err)
	}
	for i, directory := range directories {
		for _, payload := range []string{"inspect/bundle", "verify-failed/bundle", "activate/bundle", "publish/bundle", "commit/bundle", "recovery-bundle"} {
			_, err := os.Stat(filepath.Join(directory, payload))
			if !os.IsNotExist(err) {
				t.Fatalf("payload %s: %v", filepath.Join(directory, payload), err)
			}
		}
		if cached, err := completedOperatorOperation(directory, "upgrade", versions[i]); !cached || err != nil {
			t.Fatalf("cache %v %v", cached, err)
		}
		if err := matchOperatorPlan(directory, &installplan.InstallPlan{}, "/private/release"); err != nil {
			t.Fatal(err)
		}
	}
	if err := collectCompletedOperatorArtifacts(root, manifests[2], manifests[3]); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directories[0], "inventory.frozen.json"), []byte(`{"changed":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if cached, err := completedOperatorOperation(directories[0], "upgrade", versions[0]); !cached || err == nil {
		t.Fatal("changed completed identity accepted")
	}
}
func TestOperatorIncompleteAndChangedPayloadRemain(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	incomplete := retentionOperationFixture(t, root, "v1.0.0")
	completed := retentionOperationFixture(t, root, "v2.0.0")
	manifest := &automationRelease{Version: "v2.0.0", SourceCommit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if err := sealCompletedOperatorOperation(completed, "upgrade", manifest, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(completed, "recovery-bundle", "unknown"), []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := collectCompletedOperatorArtifacts(root, &automationRelease{Version: "v4.0.0"}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(incomplete, "commit", "bundle"), filepath.Join(completed, "recovery-bundle", "unknown")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
	// A terminal child is insufficient when whole-operation success is absent.
	if cached, err := completedOperatorOperation(incomplete, "upgrade", ""); cached || err != nil {
		t.Fatal(cached, err)
	}
}
func TestRuntimeCollectionHonorsUseLeaseAndOwnership(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	directory := filepath.Join(root, "runtime-"+sha)
	if err := os.MkdirAll(filepath.Join(directory, "venv", "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(directory, "venv", "bin", "ansible-playbook")
	if err := os.WriteFile(executable, []byte("fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/python3", filepath.Join(directory, "venv", "bin", "python3")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("python3", filepath.Join(directory, "venv", "bin", "python")); err != nil {
		t.Fatal(err)
	}
	if err := sealPreparedOperatorRuntime(directory, sha); err != nil {
		t.Fatal(err)
	}
	release, err := pinOperatorRuntime(executable)
	if err != nil {
		t.Fatal(err)
	}
	keep := &automationRelease{Version: "v4.0.0"}
	if err := collectCompletedOperatorArtifacts(root, keep); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(executable); err != nil {
		t.Fatal("live runtime collected", err)
	}
	release()
	if err := collectCompletedOperatorArtifacts(root, keep); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatal("obsolete proven runtime retained", err)
	}
}

func TestOperatorRuntimePython314Alias(t *testing.T) {
	for _, fixture := range []struct {
		name, target string
		valid        bool
	}{
		{"𝜋thon", "python3", true},
		{"𝜋thon", "/tmp/python3", false},
		{"𝜋thon", "../../../../python3", false},
		{"𝜋thon-extra", "python3", false},
	} {
		t.Run(fixture.name+fixture.target, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			bin := filepath.Join(directory, "venv", "bin")
			if err := os.MkdirAll(bin, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(fixture.target, filepath.Join(bin, fixture.name)); err != nil {
				t.Fatal(err)
			}
			_, err := operatorRuntimeInventory(directory)
			if fixture.valid && err != nil {
				t.Fatal(err)
			}
			if !fixture.valid && (err == nil || err.Error() != "operator_runtime_symlink_invalid") {
				t.Fatalf("unsafe runtime alias: %v", err)
			}
		})
	}
}

func TestCompletedUpgradeReplayRejectsReplacementSourceWithoutExecuting(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	directory := retentionOperationFixture(t, root, "v1.0.0")
	release := filepath.Join(root, "release")
	plan := &installplan.InstallPlan{
		SchemaVersion: installplan.CurrentSchemaVersion,
		Bridge:        installplan.BridgeConfig{SSHHost: "192.0.2.1", ReuseSpec: true},
		Exits:         []installplan.ExitNode{{SSHHost: "192.0.2.2"}},
	}
	completeDeploymentFixture(plan, release, "/pins")
	if err := installplan.ValidatePlan(plan); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(directory, "operator-plan.json")); err != nil {
		t.Fatal(err)
	}
	if err := freezeOperatorPlan(directory, plan, release); err != nil {
		t.Fatal(err)
	}
	manifest := &automationRelease{Version: "v1.0.0", SourceCommit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if err := sealCompletedOperatorOperation(directory, "upgrade", manifest, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); err != nil {
		t.Fatal(err)
	}
	if err := collectCompletedOperatorArtifacts(root, &automationRelease{Version: "v3.0.0"}); err != nil {
		t.Fatal(err)
	}
	// These executor paths cannot run; success therefore proves a metadata cache.
	if err := ansibleUpgrade(context.Background(), plan, release, directory, "/missing/python", "/missing/ansible", false); err != nil {
		t.Fatal("absent-source cache failed", err)
	}
	if err := os.Mkdir(release, 0700); err != nil {
		t.Fatal(err)
	}
	for _, contents := range []string{`{"version":"v2.0.0","source_commit":"cccccccccccccccccccccccccccccccccccccccc"}`, `malformed`} {
		if err := os.WriteFile(filepath.Join(release, "release-manifest.json"), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		if err := ansibleUpgrade(context.Background(), plan, release, directory, "/missing/python", "/missing/ansible", false); err == nil {
			t.Fatal("replaced same-path source silently cached")
		}
	}
}

func TestCompletedDuplicateCurrentVersionCopiesAreBounded(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	manifest := &automationRelease{Version: "v1.0.0", SourceCommit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	for _, name := range []string{"first", "second", "third", "fourth"} {
		container := filepath.Join(root, name)
		if err := os.Mkdir(container, 0700); err != nil {
			t.Fatal(err)
		}
		directory := retentionOperationFixture(t, container, manifest.Version)
		if err := sealCompletedOperatorOperation(directory, "upgrade", manifest, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); err != nil {
			t.Fatal(err)
		}
	}
	if err := collectCompletedOperatorArtifacts(root, manifest); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"first", "second", "third", "fourth"} {
		directory := filepath.Join(root, name, "operation-"+manifest.Version)
		if _, err := os.Stat(filepath.Join(directory, "commit", "bundle")); !os.IsNotExist(err) {
			t.Fatal("completed duplicate pinned by version", err)
		}
		if cached, err := completedOperatorOperation(directory, "upgrade", manifest.Version); !cached || err != nil {
			t.Fatal(cached, err)
		}
	}
}

func TestOperatorCompletionManyStagesUsesBoundReceiptReferences(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	directory := retentionOperationFixture(t, root, "v1.0.0")
	emptySHA := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	duplicatedInventoryBytes := 0
	for probe := 0; probe < 270; probe++ {
		stage := filepath.Join(directory, fmt.Sprintf("verify-%03d", probe))
		bundle := filepath.Join(stage, "bundle")
		if err := os.MkdirAll(bundle, 0700); err != nil {
			t.Fatal(err)
		}
		inventory := map[string]any{}
		for member := 0; member < 100; member++ {
			name := fmt.Sprintf("module_with_long_but_valid_owned_relative_name_for_inventory_regression_%03d.py", member)
			if err := os.WriteFile(filepath.Join(bundle, name), nil, 0600); err != nil {
				t.Fatal(err)
			}
			inventory[name] = []any{"file", emptySHA, 0600}
		}
		inventoryRaw, _ := json.Marshal(inventory)
		duplicatedInventoryBytes += len(inventoryRaw)
		write := func(name string, value any) {
			raw, _ := json.Marshal(value)
			if err := os.WriteFile(filepath.Join(stage, name), raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
		write("request.json", map[string]any{"variables": map[string]any{"ultra_release_version": "v1.0.0"}})
		hash, _ := sourceSHA(filepath.Join(stage, "request.json"))
		write("job.json", map[string]any{"schema_version": 1, "operation": "verify-release", "request_sha256": hash})
		write("receipt.json", map[string]any{"state": "succeeded", "request_sha256": hash})
		write(
			"bundle.retention.json",
			map[string]any{"schema": 1, "path": bundle, "identity": map[string]string{"request_sha256": hash}, "inventory": inventory},
		)
	}
	if duplicatedInventoryBytes <= 4<<20 {
		t.Fatal("fixture did not exceed original completion bound", duplicatedInventoryBytes)
	}
	manifest := &automationRelease{Version: "v1.0.0", SourceCommit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if err := sealCompletedOperatorOperation(directory, "upgrade", manifest, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(directory, operatorCompletionFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) >= 4<<20 {
		t.Fatal("completion duplicated inventory", len(raw))
	}
	if err := collectCompletedOperatorArtifacts(root, manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, "verify-269", "bundle")); !os.IsNotExist(err) {
		t.Fatal("probe payload not collected", err)
	}
	if cached, err := completedOperatorOperation(directory, "upgrade", manifest.Version); !cached || err != nil {
		t.Fatal("collected completion unavailable", cached, err)
	}
	t.Logf("formerly duplicated inventories=%d bytes, completion=%d bytes", duplicatedInventoryBytes, len(raw))
}

func TestOperatorCompletionRetiresOnlyInterruptedSupersededObservers(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	directory := retentionOperationFixture(t, root, "v1.0.0")
	makeObserver := func(name, state, code string) {
		stage := filepath.Join(directory, name)
		if err := os.Mkdir(stage, 0700); err != nil {
			t.Fatal(err)
		}
		write := func(name string, value any) {
			raw, _ := json.Marshal(value)
			if err := os.WriteFile(filepath.Join(stage, name), raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
		write(
			"request.json",
			map[string]any{
				"variables": map[string]any{
					"ultra_release_version":         "v1.0.0",
					"ultra_release_manifest_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				},
			},
		)
		hash, _ := sourceSHA(filepath.Join(stage, "request.json"))
		write("job.json", map[string]any{"schema_version": 1, "operation": "verify-release", "request_sha256": hash})
		write(
			"receipt.json",
			map[string]any{
				"state":          state,
				"code":           code,
				"request_sha256": hash,
				"result":         map[string]any{"verified": state == "succeeded"},
			},
		)
	}
	makeObserver("verify-interrupted", "running", "interrupted")
	makeObserver("verify-later-winner", "succeeded", "")
	manifest := &automationRelease{Version: "v1.0.0", SourceCommit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if err := sealCompletedOperatorOperation(directory, "upgrade", manifest, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); err != nil {
		t.Fatal(err)
	}
	if !retiredOperatorObservationValid(directory, filepath.Join(directory, "verify-interrupted")) {
		t.Fatal("superseded interruption not authenticated")
	}
	if cached, err := completedOperatorOperation(directory, "upgrade", manifest.Version); !cached || err != nil {
		t.Fatal(cached, err)
	}
	// Running mutators still block; a cancelled check cannot authenticate them.
	path := filepath.Join(directory, "activate", "receipt.json")
	raw, _ := os.ReadFile(path)
	var receipt map[string]any
	_ = json.Unmarshal(raw, &receipt)
	receipt["state"] = "running"
	receipt["code"] = "interrupted"
	raw, _ = json.Marshal(receipt)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := operatorMetadata(directory); err == nil {
		t.Fatal("running mutator accepted")
	}
}

func retentionPreflightFixture(t *testing.T, stage, state, code string, request map[string]any) {
	t.Helper()
	if err := os.MkdirAll(stage, 0700); err != nil {
		t.Fatal(err)
	}
	retentionWriteJSON(t, stage, "request.json", request)
	hash, err := sourceSHA(filepath.Join(stage, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	retentionWriteJSON(t, stage, "job.json", map[string]any{"schema_version": 1, "operation": "inspect-upgrade", "request_sha256": hash})
	retentionWriteJSON(
		t,
		stage,
		"receipt.json",
		map[string]any{
			"state":          state,
			"code":           code,
			"request_sha256": hash,
			"result":         map[string]any{"verified": state == "succeeded", "controller_enforcement_floor_absent": true},
		},
	)
}

func retentionWriteJSON(t *testing.T, stage, name string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, name), raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func retentionMutateJSON(t *testing.T, stage, name string, mutate func(map[string]any)) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(stage, name))
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	retentionWriteJSON(t, stage, name, value)
}

func retentionPreflightRequest() map[string]any {
	return map[string]any{
		"inventory": map[string]any{"all": map[string]any{}},
		"variables": map[string]any{"ultra_lock_directory": "/private/lock", "ultra_controller_enforcement_preflight_only": true},
	}
}

func TestOperatorCompletionRetiresInterruptedControllerPreflight(t *testing.T) {
	root := t.TempDir()
	_ = os.Chmod(root, 0700)
	directory := retentionOperationFixture(t, root, "v1.0.0")
	original := filepath.Join(directory, "controller-preflight-interrupted")
	winner := filepath.Join(directory, "controller-preflight-fresh")
	retentionPreflightFixture(t, original, "running", "interrupted", retentionPreflightRequest())
	manifest := &automationRelease{Version: "v1.0.0", SourceCommit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	manifestSHA := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := sealCompletedOperatorOperation(directory, "upgrade", manifest, manifestSHA); err == nil {
		t.Fatal("interrupted preflight sealed without fresh success")
	}
	retentionPreflightFixture(t, winner, "succeeded", "", retentionPreflightRequest())
	if err := sealCompletedOperatorOperation(directory, "upgrade", manifest, manifestSHA); err != nil {
		t.Fatal(err)
	}
	if !retiredOperatorObservationValid(directory, original) {
		t.Fatal("interrupted preflight not retired")
	}
	if cached, err := completedOperatorOperation(directory, "upgrade", manifest.Version); !cached || err != nil {
		t.Fatal("successful upgrade not sealed", cached, err)
	}
	// The marker authenticates both stage paths, lifecycle and immutable files.
	for _, fixture := range []struct{ stage, name string }{{original, "request.json"}, {original, "receipt.json"}, {winner, "request.json"}, {winner, "receipt.json"}} {
		t.Run(filepath.Base(fixture.stage)+"/"+fixture.name, func(t *testing.T) {
			path := filepath.Join(fixture.stage, fixture.name)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			// Whitespace preserves JSON meaning but changes the bound digest.
			if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			if retiredOperatorObservationValid(directory, original) {
				t.Fatal("changed observation accepted")
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
	proofPath := filepath.Join(original, "observation.retired.json")
	proof, err := os.ReadFile(proofPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"operation_id", "stage_directory", "winning_stage", "request_sha256", "receipt_sha256", "winning_request_sha256", "winning_receipt_sha256"} {
		retentionMutateJSON(t, original, "observation.retired.json", func(value map[string]any) { value[key] = "changed" })
		if retiredOperatorObservationValid(directory, original) {
			t.Fatalf("changed marker %s accepted", key)
		}
		if err := os.WriteFile(proofPath, proof, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOperatorControllerPreflightRetirementRejectsUnprovenStages(t *testing.T) {
	for _, name := range []string{"different-inventory", "different-lock", "extra-request", "extra-variable", "ordinary-inspect", "missing-preflight-flag", "string-preflight-flag", "false-floor", "missing-floor", "unverified", "failed-winner", "failed-original", "running-original", "missing-receipt", "malformed-receipt", "changed-receipt-hash", "wrong-schema", "wrong-operation", "arbitrary-stage", "nested-stage", "public-stage", "bootstrap"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			_ = os.Chmod(root, 0700)
			directory := retentionOperationFixture(t, root, "v1.0.0")
			original := filepath.Join(directory, "controller-preflight-interrupted")
			if name == "arbitrary-stage" {
				original = filepath.Join(directory, "inspect-interrupted")
			}
			if name == "nested-stage" {
				original = filepath.Join(directory, "nested", "controller-preflight-interrupted")
			}
			winner := filepath.Join(directory, "controller-preflight-winner")
			request := retentionPreflightRequest()
			variables := request["variables"].(map[string]any)
			switch name {
			case "different-inventory":
				request["inventory"] = map[string]any{"different": true}
			case "different-lock":
				variables["ultra_lock_directory"] = "/private/other-lock"
			case "extra-request":
				request["extra"] = true
			case "extra-variable":
				variables["ultra_release_version"] = "v1.0.0"
			case "ordinary-inspect":
				variables["ultra_controller_enforcement_preflight_only"] = false
			case "missing-preflight-flag":
				delete(variables, "ultra_controller_enforcement_preflight_only")
			case "string-preflight-flag":
				variables["ultra_controller_enforcement_preflight_only"] = "true"
			}
			retentionPreflightFixture(t, original, "running", "interrupted", request)
			// Invalid preflight shapes must fail even when the winner is identical.
			winnerRequest := retentionPreflightRequest()
			if name == "extra-request" || name == "extra-variable" || name == "ordinary-inspect" || name == "missing-preflight-flag" ||
				name == "string-preflight-flag" {
				winnerRequest = request
			}
			retentionPreflightFixture(t, winner, "succeeded", "", winnerRequest)
			switch name {
			case "false-floor", "missing-floor", "unverified":
				retentionMutateJSON(t, winner, "receipt.json", func(value map[string]any) {
					result := value["result"].(map[string]any)
					switch name {
					case "missing-floor":
						delete(result, "controller_enforcement_floor_absent")
					case "false-floor":
						result["controller_enforcement_floor_absent"] = false
					case "unverified":
						result["verified"] = false
					}
				})
			case "failed-winner":
				retentionMutateJSON(t, winner, "receipt.json", func(value map[string]any) { value["state"] = "failed" })
			case "failed-original":
				retentionMutateJSON(t, original, "receipt.json", func(value map[string]any) { value["state"] = "failed" })
			case "running-original":
				retentionMutateJSON(t, original, "receipt.json", func(value map[string]any) { delete(value, "code") })
			case "missing-receipt":
				if err := os.Remove(filepath.Join(original, "receipt.json")); err != nil {
					t.Fatal(err)
				}
			case "malformed-receipt":
				if err := os.WriteFile(filepath.Join(original, "receipt.json"), []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			case "changed-receipt-hash":
				retentionMutateJSON(t, original, "receipt.json", func(value map[string]any) { value["request_sha256"] = "changed" })
			case "wrong-schema":
				retentionMutateJSON(t, original, "job.json", func(value map[string]any) { value["schema_version"] = 2 })
			case "wrong-operation":
				retentionMutateJSON(t, original, "job.json", func(value map[string]any) { value["operation"] = "upgrade" })
			case "public-stage":
				if err := os.Chmod(original, 0755); err != nil {
					t.Fatal(err)
				}
			}
			kind := "upgrade"
			if name == "bootstrap" {
				kind = "bootstrap"
			}
			manifest := &automationRelease{Version: "v1.0.0", SourceCommit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
			if err := retireInterruptedOperatorObservations(directory, kind, manifest, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(original, "observation.retired.json")); !os.IsNotExist(err) {
				t.Fatal("unproven stage retired", err)
			}
			if retiredOperatorObservationValid(directory, original) {
				t.Fatal("unproven stage accepted")
			}
			if name != "failed-original" {
				if _, err := operatorMetadata(directory); err == nil {
					t.Fatal("unretired incomplete stage accepted")
				}
			}
		})
	}
}
