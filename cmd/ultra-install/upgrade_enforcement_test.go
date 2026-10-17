package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestControllerEnforcementProtocol(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(python, filepath.Join("..", "..", "scripts", "test-controller-enforcement.py"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("controller enforcement checks failed: %v\n%s", err, output)
	}
}

func enforcementFixture(t *testing.T) (string, string, *automationRelease, map[string]any, map[string]any) {
	t.Helper()
	root := t.TempDir()
	directory, release := filepath.Join(root, "upgrade-v0.0.1"), filepath.Join(root, "release")
	for _, path := range []string{directory, release} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	manifest := brokerTestManifest("v0.0.1", strings.Repeat("1", 40), "a")
	for _, asset := range append(manifest.Assets[:0:0], manifest.Assets...) {
		asset.Name = strings.ReplaceAll(asset.Name, "amd64", "arm64")
		manifest.Assets = append(manifest.Assets, asset)
	}
	retentionWriteJSON(t, release, "release-manifest.json", manifest)
	retentionWriteJSON(t, directory, "operator-plan.json", map[string]any{"source": "frozen"})
	inventory := map[string]any{"all": map[string]any{}}
	spec, err := upgradeEnforcementSpec(directory, release, manifest, inventory)
	if err != nil {
		t.Fatal(err)
	}
	entry := spec["candidates"].(map[string]any)["amd64"].(map[string]any)
	proof := map[string]any{"schema": float64(1), "operation_id": spec["operation_id"],
		"scope_sha256": spec["scope_sha256"], "manifest_sha256": spec["manifest_sha256"],
		"machine_sha256": strings.Repeat("b", 64), "ledger_sha256": strings.Repeat("c", 64),
		"source_lifecycle": map[string]any{"id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "phase": "released"},
		"candidate":        entry["identity"], "rollback": map[string]any{
			"directory": "/opt/ultra-ansible/releases/managed-v0.0.0", "unit": "fixture",
			"unit_sha256": digestSHA256([]byte("fixture")), "installer_sha256": strings.Repeat("d", 64),
			"runtime_sha256": strings.Repeat("e", 64), "tree_sha256": strings.Repeat("f", 64)}}
	return directory, release, manifest, spec, proof
}

func TestUpgradeEnforcementProofBindsReleasePlanAndCandidate(t *testing.T) {
	directory, release, manifest, spec, proof := enforcementFixture(t)
	if err := validateEnforcementProof(proof, spec); err != nil {
		t.Fatal(err)
	}
	retentionWriteJSON(t, directory, enforcementProofFile, proof)
	if _, err := upgradeEnforcementSpec(directory, release, manifest, map[string]any{"all": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"operation_id", "scope_sha256", "manifest_sha256", "ledger_sha256", "machine_sha256"} {
		t.Run(field, func(t *testing.T) {
			raw, _ := json.Marshal(proof)
			var changed map[string]any
			_ = json.Unmarshal(raw, &changed)
			changed[field] = "changed"
			if validateEnforcementProof(changed, spec) == nil {
				t.Fatal("changed proof accepted")
			}
		})
	}
	retentionWriteJSON(t, directory, "operator-plan.json", map[string]any{"source": "changed"})
	if _, err := upgradeEnforcementSpec(directory, release, manifest, map[string]any{"all": map[string]any{}}); err == nil {
		t.Fatal("proof accepted after frozen plan drift")
	}
}

func TestUpgradeEnforcementProofRejectsCandidateAndRollbackDrift(t *testing.T) {
	_, _, _, spec, proof := enforcementFixture(t)
	for _, kind := range []string{"candidate", "rollback", "unit", "source-lifecycle", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			raw, _ := json.Marshal(proof)
			var changed map[string]any
			_ = json.Unmarshal(raw, &changed)
			switch kind {
			case "candidate":
				changed["candidate"].(map[string]any)["installer_sha256"] = strings.Repeat("0", 64)
			case "rollback":
				changed["rollback"].(map[string]any)["runtime_sha256"] = "unknown"
			case "unit":
				changed["rollback"].(map[string]any)["unit"] = "changed"
			case "source-lifecycle":
				changed["source_lifecycle"].(map[string]any)["phase"] = "applying"
			case "unknown":
				changed["claim"] = true
			}
			if validateEnforcementProof(changed, spec) == nil {
				t.Fatal("unbound identity accepted")
			}
		})
	}
}

func TestEnforcementPreflightRetentionRequiresExactProofScope(t *testing.T) {
	directory, _, _, spec, proof := enforcementFixture(t)
	original, winner := filepath.Join(directory, "controller-preflight-original"), filepath.Join(directory, "controller-preflight-winner")
	request := func(s map[string]any) map[string]any {
		return map[string]any{"inventory": map[string]any{"all": map[string]any{}}, "variables": map[string]any{
			"ultra_lock_directory": "/private/lock", "ultra_controller_enforcement_preflight_only": true,
			"ultra_controller_enforcement_spec": s}}
	}
	retentionPreflightFixture(t, original, "running", "interrupted", request(spec))
	winningSpec := map[string]any{}
	for key, value := range spec {
		winningSpec[key] = value
	}
	winningSpec["proof"], winningSpec["phase"] = proof, "reserved"
	retentionPreflightFixture(t, winner, "succeeded", "", request(winningSpec))
	retentionMutateJSON(t, winner, "receipt.json", func(value map[string]any) {
		value["result"] = map[string]any{"verified": true, "controller_enforcement_floor_absent": false,
			"controller_enforcement_proof": proof}
	})
	left, err := readOperatorObservation(original)
	if err != nil {
		t.Fatal(err)
	}
	right, err := readOperatorObservation(winner)
	if err != nil || !sameOperatorObservationRelease(left, right) {
		t.Fatal("fresh exact scoped proof not recognized", err)
	}
	right.enforcementScope = strings.Repeat("0", 64)
	if sameOperatorObservationRelease(left, right) {
		t.Fatal("foreign enforcement observation retired interruption")
	}
}

// Child exits at the release/complete boundary, without running deferred cleanup.
func TestEnforcementReleaseWindowProcessHelper(t *testing.T) {
	if len(os.Args) < 3 || !strings.HasPrefix(os.Args[len(os.Args)-2], "--enforcement-release-") {
		return
	}
	directory := os.Args[len(os.Args)-1]
	phase := "released"
	if os.Args[len(os.Args)-2] == "--enforcement-release-before" {
		phase = "checking"
	}
	raw, _ := json.Marshal(map[string]any{"id": lifecycleID(directory), "phase": phase})
	if err := os.WriteFile(filepath.Join(directory, "mock-remote-lifecycle.json"), raw, 0600); err != nil {
		os.Exit(74)
	}
	os.Exit(73)
}

func TestEnforcementReleaseWindowCompletionOnlyAfterInterruptedProcess(t *testing.T) {
	for _, window := range []string{"before", "after"} {
		t.Run(window, func(t *testing.T) {
			root := t.TempDir()
			_ = os.Chmod(root, 0700)
			directory := retentionOperationFixture(t, root, "v0.0.1")
			manifest := &automationRelease{Version: "v0.0.1", SourceCommit: strings.Repeat("a", 40)}
			inventory := map[string]any{"all": map[string]any{}}
			committedInventory := map[string]any{"all": map[string]any{"derived_count": 2, "previous_manifest": manifest}}
			retentionWriteJSON(t, directory, "inventory.frozen.json", committedInventory)
			_, _, _, spec, proof := enforcementFixture(t)
			spec["operation_id"], proof["operation_id"] = lifecycleID(directory), lifecycleID(directory)
			spec["scope_sha256"], proof["scope_sha256"] = strings.Repeat("c", 64), strings.Repeat("c", 64)
			spec["manifest_sha256"], proof["manifest_sha256"] = strings.Repeat("b", 64), strings.Repeat("b", 64)
			spec["proof"] = proof
			variables := map[string]any{
				"ultra_upgrade_observed_at":         int64(25),
				"ultra_release_version":             manifest.Version,
				"ultra_release_manifest_sha256":     spec["manifest_sha256"],
				"ultra_release_manifest":            manifest,
				"ultra_controller_enforcement_spec": spec,
			}
			retentionWriteJSON(t, directory, enforcementProofFile, spec["proof"])
			for _, stage := range []string{"activate", "publish", "commit"} {
				values := map[string]any{}
				for key, value := range variables {
					values[key] = value
				}
				if stage == "publish" || stage == "commit" {
					values["ultra_upgrade_observed_at"] = 100
				}
				path := filepath.Join(directory, stage)
				retentionWriteJSON(t, path, "request.json", map[string]any{"inventory": committedInventory, "variables": values})
				hash, _ := sourceSHA(filepath.Join(path, "request.json"))
				retentionMutateJSON(
					t,
					path,
					"job.json",
					func(v map[string]any) { v["request_sha256"], v["binary_sha256"] = hash, strings.Repeat("d", 64) },
				)
				retentionMutateJSON(t, path, "receipt.json", func(v map[string]any) {
					v["request_sha256"], v["binary_sha256"] = hash, strings.Repeat("d", 64)
					v["result"] = map[string]any{"verified": true, "activated_at": 100}
				})
				retentionMutateJSON(
					t,
					path,
					"bundle.retention.json",
					func(v map[string]any) { v["identity"] = map[string]any{"request_sha256": hash} },
				)
			}
			resumeStage := filepath.Join(directory, "resume-fixture")
			if err := os.Mkdir(resumeStage, 0700); err != nil {
				t.Fatal(err)
			}
			retentionWriteJSON(
				t,
				resumeStage,
				"request.json",
				map[string]any{"inventory": inventory, "variables": map[string]any{"ultra_lock_directory": root}},
			)
			resumeHash, _ := sourceSHA(filepath.Join(resumeStage, "request.json"))
			retentionWriteJSON(
				t,
				resumeStage,
				"job.json",
				map[string]any{"schema_version": 1, "operation": "resume-automation", "request_sha256": resumeHash},
			)
			retentionWriteJSON(t, resumeStage, "receipt.json", map[string]any{"state": "succeeded", "request_sha256": resumeHash})
			preflightRequest := map[string]any{"inventory": inventory, "variables": map[string]any{
				"ultra_lock_directory": root, "ultra_controller_enforcement_preflight_only": true,
				"ultra_controller_enforcement_spec": spec}}
			interrupted := filepath.Join(directory, "controller-preflight-interrupted")
			winner := filepath.Join(directory, "controller-preflight-winner")
			retentionPreflightFixture(t, interrupted, "running", "interrupted", preflightRequest)
			retentionPreflightFixture(t, winner, "succeeded", "", preflightRequest)
			retentionMutateJSON(t, winner, "receipt.json", func(value map[string]any) {
				value["result"] = map[string]any{"verified": true, "controller_enforcement_floor_absent": false,
					"controller_enforcement_proof": proof}
			})
			verifyInterrupted := filepath.Join(directory, "verify-interrupted")
			for _, observation := range []struct{ path, state, code string }{
				{verifyInterrupted, "running", "interrupted"},
				{filepath.Join(directory, "verify-winner"), "succeeded", ""},
			} {
				retentionPreflightFixture(
					t,
					observation.path,
					observation.state,
					observation.code,
					map[string]any{"variables": map[string]any{
						"ultra_release_version": manifest.Version, "ultra_release_manifest_sha256": spec["manifest_sha256"]}},
				)
				retentionMutateJSON(t, observation.path, "job.json", func(v map[string]any) { v["operation"] = "verify-release" })
			}
			if _, err := operatorMetadata(directory); err == nil {
				t.Fatal("unretired interrupted preflight unexpectedly accepted")
			}
			observations := 0
			observe := func() (bool, error) {
				observations++
				if spec["phase"] != "completion" {
					t.Fatal("not a completion-only observation")
				}
				raw, err := os.ReadFile(filepath.Join(directory, "mock-remote-lifecycle.json"))
				var remote map[string]any
				if err != nil || json.Unmarshal(raw, &remote) != nil || remote["id"] != lifecycleID(directory) {
					return false, errors.New("mock remote unverified")
				}
				return remote["phase"] == "released", nil
			}
			if done, err := recoverEnforcementCompletionWith(directory, manifest, inventory, spec, observe, func() error { t.Fatal("unexpected lifecycle release"); return nil }); err != nil ||
				done ||
				observations != 0 {
				t.Fatal("missing intent accepted", err)
			}
			// Production overwrites the live watermark after activation, whereas
			// activate/request.json retains the initial inspection watermark.
			variables["ultra_upgrade_observed_at"] = int64(100)
			if err := verifyCommittedUpgradeContinuation(directory, committedInventory, variables); err == nil {
				t.Fatal("post-activation watermark unexpectedly matched frozen activation")
			}
			if err := saveEnforcementReleaseIntent(directory, committedInventory, variables, 26); err == nil {
				t.Fatal("wrong initial watermark accepted")
			}
			if _, err := os.Stat(filepath.Join(directory, enforcementReleaseIntentFile)); !os.IsNotExist(err) {
				t.Fatal("invalid initial watermark published intent")
			}
			retentionMutateJSON(t, filepath.Join(directory, "publish"), "receipt.json", func(v map[string]any) { v["state"] = "failed" })
			if err := saveEnforcementReleaseIntent(directory, committedInventory, variables, 25); err == nil {
				t.Fatal("failed winning chain allowed release intent")
			}
			if _, err := os.Stat(filepath.Join(interrupted, "observation.retired.json")); !os.IsNotExist(err) {
				t.Fatal("observation retired before winning chain validation")
			}
			retentionMutateJSON(t, filepath.Join(directory, "publish"), "receipt.json", func(v map[string]any) { v["state"] = "succeeded" })
			// The intent is written after a successful schedule-restore callback in production.
			if err := saveEnforcementReleaseIntent(directory, committedInventory, variables, 25); err != nil {
				t.Fatal(err)
			}
			if !retiredOperatorObservationValid(directory, interrupted) || !retiredOperatorObservationValid(directory, verifyInterrupted) {
				t.Fatal("release intent did not authenticate superseded preflight before release")
			}
			var intent enforcementReleaseIntent
			intentRaw, err := os.ReadFile(filepath.Join(directory, enforcementReleaseIntentFile))
			if err != nil || json.Unmarshal(intentRaw, &intent) != nil ||
				(intent.Metadata["controller-preflight-interrupted/observation.retired.json"] == "" || intent.Metadata["verify-interrupted/observation.retired.json"] == "") {
				t.Fatal("release intent omitted retirement evidence", err)
			}
			child := exec.Command(
				os.Args[0],
				"-test.run=^TestEnforcementReleaseWindowProcessHelper$",
				"--",
				"--enforcement-release-"+window,
				directory,
			)
			err = child.Run()
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 73 {
				t.Fatalf("fault injection: %v", err)
			}
			if _, err := os.Stat(filepath.Join(directory, operatorCompletionFile)); !os.IsNotExist(err) {
				t.Fatal("crash falsely completed operation")
			}
			// A failed release keeps the intent but cannot seal completion.
			if done, err := recoverEnforcementCompletionWith(directory, manifest, inventory, spec, func() (bool, error) { return false, nil }, func() error { return errors.New("injected release failure") }); err == nil ||
				done {
				t.Fatal("failed release completed", err)
			}
			// Remote observation authenticates own released ID and candidate (Python test
			// exercises the actual guard); here assert this is the only callback invoked.
			releases := 0
			release := func() error {
				releases++
				retentionWriteJSON(
					t,
					directory,
					"mock-remote-lifecycle.json",
					map[string]any{"id": lifecycleID(directory), "phase": "released"},
				)
				return nil
			}
			expectedObservations, expectedReleases := 1, 0
			if window == "before" {
				expectedObservations, expectedReleases = 2, 1
			}
			if done, err := recoverEnforcementCompletionWith(directory, manifest, inventory, spec, observe, release); err != nil || !done ||
				observations != expectedObservations ||
				releases != expectedReleases {
				t.Fatal("completion-only recovery failed", done, err)
			}
			if cached, err := completedOperatorOperation(directory, "upgrade", "v0.0.1"); !cached || err != nil {
				t.Fatal("completion not sealed", err)
			}
			retentionMutateJSON(t, filepath.Join(directory, "commit"), "receipt.json", func(v map[string]any) { v["state"] = "failed" })
			if _, err := recoverEnforcementCompletionWith(directory, manifest, inventory, spec, observe, func() error { t.Fatal("unexpected lifecycle release"); return nil }); err == nil ||
				observations != expectedObservations {
				t.Fatal("changed frozen commit accepted")
			}
		})
	}
}
