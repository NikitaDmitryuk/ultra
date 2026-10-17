package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/google/uuid"

	ansibleassets "github.com/NikitaDmitryuk/ultra/deploy/ansible"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

const enforcementProofFile = "controller-enforcement.json"

func validEnforcementSHA(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && strings.ToLower(value) == value
}

// This identity is derived only from the verified release and frozen operation.
// Neither a caller-selected predecessor nor a capability boolean can authorize
// crossing the retirement floor.
func upgradeEnforcementSpec(directory, release string, manifest *automationRelease, inventory map[string]any) (map[string]any, error) {
	manifestSHA, err := sourceSHA(filepath.Join(release, "release-manifest.json"))
	if err != nil {
		return nil, err
	}
	planSHA, err := sourceSHA(filepath.Join(directory, "operator-plan.json"))
	if err != nil {
		return nil, err
	}
	template, err := ansibleassets.Bundle.ReadFile("roles/controller/templates/ultra-ansible-controller.service.j2")
	if err != nil {
		return nil, err
	}
	target := managedControllerDirectory(manifest.Version)
	unitSHA := digestSHA256([]byte(strings.ReplaceAll(string(template), "{{ ultra_controller_directory }}", target)))
	candidates := map[string]any{}
	for _, architecture := range []string{"amd64", "arm64"} {
		installer, err := upgradeAsset(manifest, "ultra-install-linux-"+architecture)
		if err != nil {
			return nil, err
		}
		runtime, err := upgradeAsset(manifest, "ultra-ansible-runtime-linux-"+architecture+".tar.gz")
		if err != nil {
			return nil, err
		}
		candidates[architecture] = map[string]any{
			"source": filepath.Join(release, installer.Name),
			"identity": map[string]any{"directory": target, "architecture": architecture,
				"installer_sha256": installer.SHA, "runtime_sha256": runtime.SHA, "unit_sha256": unitSHA},
		}
	}
	scope, err := json.Marshal(map[string]any{"operation_id": lifecycleID(directory), "plan_sha256": planSHA,
		"manifest_sha256": manifestSHA, "inventory": inventory, "candidates": candidates})
	if err != nil {
		return nil, err
	}
	spec := map[string]any{"operation_id": lifecycleID(directory), "scope_sha256": digestSHA256(scope),
		"manifest_sha256": manifestSHA, "candidates": candidates, "proof": map[string]any{}, "phase": "preflight"}
	path := filepath.Join(directory, enforcementProofFile)
	if _, err := os.Lstat(path); err == nil {
		if err = operatorPrivate(path, false); err != nil {
			return nil, err
		}
		raw, err := os.ReadFile(path)
		var proof map[string]any
		if err != nil || len(raw) > 1<<20 || json.Unmarshal(raw, &proof) != nil || validateEnforcementProof(proof, spec) != nil {
			return nil, errors.New("upgrade_controller_enforcement_proof_changed")
		}
		spec["proof"] = proof
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return spec, nil
}

func validateEnforcementProof(proof, spec map[string]any) error {
	fail := errors.New("upgrade_controller_enforcement_proof_unverified")
	if len(proof) != 9 || proof["schema"] != float64(1) || proof["operation_id"] != spec["operation_id"] ||
		proof["scope_sha256"] != spec["scope_sha256"] || proof["manifest_sha256"] != spec["manifest_sha256"] {
		return fail
	}
	for _, key := range []string{"ledger_sha256", "machine_sha256"} {
		value, ok := proof[key].(string)
		if !ok || !validEnforcementSHA(value) {
			return fail
		}
	}
	candidate, ok := proof["candidate"].(map[string]any)
	if !ok {
		return fail
	}
	architecture, _ := candidate["architecture"].(string)
	candidates, _ := spec["candidates"].(map[string]any)
	entry, _ := candidates[architecture].(map[string]any)
	if entry == nil || !reflect.DeepEqual(candidate, entry["identity"]) {
		return fail
	}
	rollback, ok := proof["rollback"].(map[string]any)
	if !ok || len(rollback) != 6 {
		return fail
	}
	for _, key := range []string{"installer_sha256", "runtime_sha256", "unit_sha256", "tree_sha256"} {
		value, ok := rollback[key].(string)
		if !ok || !validEnforcementSHA(value) {
			return fail
		}
	}
	unit, unitOK := rollback["unit"].(string)
	directory, directoryOK := rollback["directory"].(string)
	if !unitOK || !directoryOK || len(unit) > 65536 || digestSHA256([]byte(unit)) != rollback["unit_sha256"] ||
		!strings.HasPrefix(directory, "/opt/ultra-ansible/releases/") || filepath.Clean(directory) != directory ||
		filepath.Dir(directory) != "/opt/ultra-ansible/releases" {
		return fail
	}
	lifecycle, ok := proof["source_lifecycle"].(map[string]any)
	if !ok || len(lifecycle) != 2 || lifecycle["phase"] != "released" {
		return fail
	}
	id, ok := lifecycle["id"].(string)
	parsed, err := uuid.Parse(id)
	if !ok || err != nil || parsed.String() != id {
		return fail
	}
	return nil
}

func runEnforcementPreflight(
	ctx context.Context,
	inventory map[string]any,
	directory, lock, python, executable string,
	spec map[string]any,
) error {
	_, err := runEnforcementObservation(ctx, inventory, directory, lock, python, executable, spec)
	return err
}

func runEnforcementObservation(
	ctx context.Context, inventory map[string]any, directory, lock, python, executable string, spec map[string]any,
) (bool, error) {
	stage, err := os.MkdirTemp(directory, "controller-preflight-")
	if err != nil {
		return false, err
	}
	if err = os.Remove(stage); err != nil {
		return false, err
	}
	receipt, err := deployansible.RunLocal(ctx, "inspect-upgrade", inventory, map[string]any{
		"ultra_lock_directory": lock, "ultra_controller_enforcement_preflight_only": true,
		"ultra_controller_enforcement_spec": spec,
	}, stage, python, executable)
	if err != nil {
		return false, err
	}
	values := receipt.Result.Values
	if values["verified"] != true {
		return false, errors.New("upgrade_controller_enforcement_preflight_unverified")
	}
	if values["controller_enforcement_floor_absent"] == true {
		prior, _ := spec["proof"].(map[string]any)
		if len(prior) != 0 {
			return false, errors.New("upgrade_controller_enforcement_floor_disappeared")
		}
		return false, nil
	}
	proof, ok := values["controller_enforcement_proof"].(map[string]any)
	if !ok || validateEnforcementProof(proof, spec) != nil {
		return false, errors.New("upgrade_controller_enforcement_preflight_unverified")
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return false, err
	}
	if err = writeUpgradeInput(filepath.Join(directory, enforcementProofFile), raw); err != nil {
		return false, err
	}
	spec["proof"] = proof
	return values["controller_enforcement_completion_ready"] == true, nil
}

const enforcementReleaseIntentFile = "controller-enforcement-release-intent.json"

type enforcementReleaseIntent struct {
	Schema    int               `json:"schema"`
	Operation string            `json:"operation_id"`
	Scope     string            `json:"scope_sha256"`
	Manifest  string            `json:"manifest_sha256"`
	Metadata  map[string]string `json:"metadata"`
}

// Written only after successful commit, domain/effect finalization and schedule
// restoration. This authorizes a completion check and, if needed, only its pending release;
// never a reservation or replay of upgrade stages.
func saveEnforcementReleaseIntent(directory string, inventory, variables map[string]any, initialObservedAt int64) error {
	spec, ok := variables["ultra_controller_enforcement_spec"].(map[string]any)
	if !ok {
		return nil
	}
	proof, _ := spec["proof"].(map[string]any)
	if len(proof) == 0 {
		return nil
	}
	// The live variables now carry activated_at for post-activation stages.
	// Activate froze the earlier inspection watermark; retain every other byte
	// and let the verifier derive commit's watermark from its activation receipt.
	activationVariables := make(map[string]any, len(variables))
	for key, value := range variables {
		activationVariables[key] = value
	}
	activationVariables["ultra_upgrade_observed_at"] = initialObservedAt
	if err := verifyCommittedUpgradeContinuation(directory, inventory, activationVariables); err != nil {
		return err
	}
	if present, err := verifyEnforcementReleaseIntent(directory, spec); present || err != nil {
		return err
	}
	manifest, ok := variables["ultra_release_manifest"].(*automationRelease)
	manifestSHA, shaOK := spec["manifest_sha256"].(string)
	if !ok || manifest == nil || !shaOK {
		return errors.New("upgrade_controller_enforcement_release_identity_invalid")
	}
	if err := operatorWinningChain(directory, "upgrade", manifest, manifestSHA); err != nil {
		return err
	}
	// Exact superseded read-only observations must be durably retired before
	// metadata is collected, so interrupted checks cannot deadlock release.
	// The existing retention verifier still rejects mutators and unknown jobs.
	if err := retireInterruptedOperatorObservations(directory, "upgrade", manifest, manifestSHA); err != nil {
		return err
	}
	metadata, err := operatorMetadata(directory)
	if err != nil {
		return err
	}
	if !enforcementResumeEvidence(directory, metadata) {
		return errors.New("upgrade_controller_enforcement_resume_unverified")
	}
	intent := enforcementReleaseIntent{1, lifecycleID(directory), spec["scope_sha256"].(string), spec["manifest_sha256"].(string), metadata}
	raw, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	return writeUpgradeInput(filepath.Join(directory, enforcementReleaseIntentFile), raw)
}

func verifyEnforcementReleaseIntent(directory string, spec map[string]any) (bool, error) {
	path := filepath.Join(directory, enforcementReleaseIntentFile)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return false, nil
	}
	invalid := errors.New("upgrade_controller_enforcement_release_intent_invalid")
	if err := operatorPrivate(path, false); err != nil {
		return true, invalid
	}
	raw, err := readBootstrapGenerationInput(path)
	var intent enforcementReleaseIntent
	if err != nil || json.Unmarshal(raw, &intent) != nil || intent.Schema != 1 ||
		intent.Operation != lifecycleID(directory) || intent.Scope != spec["scope_sha256"] ||
		intent.Manifest != spec["manifest_sha256"] || len(intent.Metadata) == 0 ||
		intent.Metadata[enforcementProofFile] == "" || intent.Metadata["inventory.frozen.json"] == "" || intent.Metadata["activate/request.json"] == "" {
		return true, invalid
	}
	for relative, expected := range intent.Metadata {
		if filepath.IsAbs(relative) || filepath.Clean(relative) != relative || strings.HasPrefix(relative, "../") ||
			!validEnforcementSHA(expected) {
			return true, invalid
		}
		file := filepath.Join(directory, relative)
		if operatorPrivate(file, false) != nil {
			return true, invalid
		}
		actual, hashErr := sourceSHA(file)
		if hashErr != nil || actual != expected {
			return true, invalid
		}
	}
	if !enforcementResumeEvidence(directory, intent.Metadata) {
		return true, invalid
	}
	return true, nil
}

func enforcementResumeEvidence(directory string, metadata map[string]string) bool {
	for relative := range metadata {
		if !strings.HasPrefix(relative, "resume-") || filepath.Base(relative) != "job.json" {
			continue
		}
		stage := filepath.Dir(relative)
		if strings.Contains(stage, string(filepath.Separator)) || metadata[stage+"/request.json"] == "" ||
			metadata[stage+"/receipt.json"] == "" {
			continue
		}
		jobRaw, jobErr := readBootstrapGenerationInput(filepath.Join(directory, relative))
		receiptRaw, receiptErr := readBootstrapGenerationInput(filepath.Join(directory, stage, "receipt.json"))
		var job struct {
			Operation string `json:"operation"`
		}
		var receipt struct {
			State string `json:"state"`
		}
		if jobErr == nil && receiptErr == nil && json.Unmarshal(jobRaw, &job) == nil && json.Unmarshal(receiptRaw, &receipt) == nil &&
			job.Operation == "resume-automation" &&
			receipt.State == "succeeded" {
			return true
		}
	}
	return false
}

// The only retry that accepts an already selected candidate and released own ID.
// Frozen successful receipts and the durable pre-release intent are mandatory.
func recoverEnforcementCompletion(
	ctx context.Context, p *installplan.InstallPlan, directory, lock, python, executable string, manifest *automationRelease,
	inventory, spec map[string]any,
) (bool, error) {
	return recoverEnforcementCompletionWith(directory, manifest, inventory, spec, func() (bool, error) {
		return runEnforcementObservation(ctx, inventory, directory, lock, python, executable, spec)
	}, func() error {
		return ansibleLifecycle(ctx, p, inventory, directory, python, executable, "released", false)
	})
}

func recoverEnforcementCompletionWith(
	directory string,
	manifest *automationRelease,
	inventory, spec map[string]any,
	observe func() (bool, error),
	release func() error,
) (bool, error) {
	present, err := verifyEnforcementReleaseIntent(directory, spec)
	if !present || err != nil {
		return false, err
	}
	raw, err := readBootstrapGenerationInput(filepath.Join(directory, "activate", "request.json"))
	var request struct {
		Inventory json.RawMessage            `json:"inventory"`
		Variables map[string]json.RawMessage `json:"variables"`
	}
	frozenRaw, frozenErr := readBootstrapGenerationInput(filepath.Join(directory, "inventory.frozen.json"))
	if err != nil || frozenErr != nil || json.Unmarshal(raw, &request) != nil || string(request.Inventory) != string(frozenRaw) {
		return false, errors.New("upgrade_controller_enforcement_committed_request_invalid")
	}
	// Preserve every frozen nested JSON value byte-for-byte, including typed
	// manifest fields and inventory values added after the initial preflight.
	var entries map[string]json.RawMessage
	if json.Unmarshal(request.Inventory, &entries) != nil {
		return false, errors.New("upgrade_controller_enforcement_committed_request_invalid")
	}
	frozen, variables := map[string]any{}, map[string]any{}
	for key, value := range entries {
		frozen[key] = value
	}
	for key, value := range request.Variables {
		variables[key] = value
	}
	if err = verifyCommittedUpgradeContinuation(directory, frozen, variables); err != nil {
		return false, err
	}
	manifestSHA, _ := spec["manifest_sha256"].(string)
	if err = operatorWinningChain(directory, "upgrade", manifest, manifestSHA); err != nil {
		return false, err
	}
	spec["phase"] = "completion"
	defer func() { spec["phase"] = "preflight" }()
	ready, err := observe()
	if err != nil {
		return false, err
	}
	if !ready {
		// The exact intent already certifies finalization and successful resume.
		// Finish only its pending release; never reserve or replay the upgrade.
		if err = release(); err != nil {
			return false, err
		}
		ready, err = observe()
		if err != nil {
			return false, err
		}
		if !ready {
			return false, errors.New("upgrade_controller_enforcement_release_unconfirmed")
		}
	}
	return true, sealCompletedOperatorOperation(directory, "upgrade", manifest, manifestSHA)
}
