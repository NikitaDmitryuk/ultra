package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

const retainPreparedControllerPolicy = "retain-prepared-candidate"

// A completed recovery is the real predecessor for subsequent independent
// upgrades. Only this still-running prepared upgrade receives this policy.
func preparedControllerEnvelope(root string, cgroup []byte) (string, *deployOperationRequest, error) {
	fail := errors.New("prepared_controller_policy_supervisor_unverified")
	path := filepath.Join(root, "current.json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return "", nil, nil
	} else if err != nil {
		return "", nil, err
	}
	raw, err := readRebuildInput(path, true)
	if err != nil {
		return "", nil, err
	}
	var pointer struct {
		Schema  int    `json:"schema"`
		Request string `json:"request_sha256"`
	}
	if decodeRetainedReconcile(raw, &pointer) != nil || pointer.Schema != 1 || !runtimeHostValidDigest(pointer.Request) {
		return "", nil, fail
	}
	directory := filepath.Join(root, pointer.Request)
	raw, err = readRebuildInput(filepath.Join(directory, "request.json"), true)
	var envelope deployOperationRequest
	if err != nil || digestSHA256(raw) != pointer.Request || decodeRetainedReconcile(raw, &envelope) != nil {
		return "", nil, fail
	}
	state, err := readDeployOperation(directory, envelope)
	if err != nil {
		return "", nil, err
	}
	if envelope.Schema == 1 && envelope.Preparation == nil {
		return "", nil, nil
	}
	if state.State == "completed" && state.Stage == "status" {
		return "", nil, nil
	}
	if envelope.Schema != 2 || envelope.Preparation == nil || state.State != "running" || state.Stage != "upgrade" {
		return "", nil, fail
	}
	for _, line := range strings.Split(string(cgroup), "\n") {
		if strings.HasSuffix(line, ":/system.slice/ultra-deploy-"+pointer.Request+".service") {
			return pointer.Request, &envelope, nil
		}
	}
	return "", nil, fail
}

func recoveryPreparedControllerPolicy(
	ctx context.Context,
	p *installplan.InstallPlan,
	directory, release string,
	inventory, spec map[string]any,
) (map[string]any, error) {
	cgroup, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return nil, err
	}
	envelopeSHA, envelope, err := preparedControllerEnvelope(deployOperationsRoot, cgroup)
	if err != nil || envelope == nil {
		return nil, err
	}
	r := *envelope.Preparation
	if directory == "" || release != r.ToolsReleaseDirectory || spec == nil {
		return nil, errors.New("prepared_controller_policy_operation_changed")
	}
	if _, err = validateRecoveryPreparationRequest(r); err != nil {
		return nil, err
	}
	plan, err := recoveryUpgradePlanWithMode(r, envelope.Args, false)
	if err != nil {
		return nil, err
	}
	if directory != plan.directory || matchOperatorPlan(directory, p, release) != nil {
		return nil, errors.New("prepared_controller_policy_plan_changed")
	}
	descriptor, err := readRecoveryBrokerPreflight(r, plan)
	if err != nil {
		return nil, err
	}
	encoded, _ := json.Marshal(inventory)
	if descriptor.InventorySHA256 != digestSHA256(encoded) || descriptor.ScopeSHA256 != spec["scope_sha256"] ||
		descriptor.OperationID != lifecycleID(directory) {
		return nil, errors.New("prepared_controller_policy_scope_changed")
	}
	if err = verifyRecoveryBrokerHandoff(ctx, r, envelope.Args); err != nil {
		return nil, err
	}
	terminalSHA, err := sourceSHA(filepath.Join(r.StateDirectory, "broker-handoff.json"))
	if err != nil {
		return nil, err
	}
	candidate := spec["proof"].(map[string]any)["candidate"]
	return map[string]any{
		"policy":                   retainPreparedControllerPolicy,
		"envelope_sha256":          envelopeSHA,
		"preparation_sha256":       r.digest(),
		"handoff_sha256":           terminalSHA,
		"enforcement_sha256":       descriptor.EnforcementSHA256,
		"operation_id":             descriptor.OperationID,
		"source_id":                descriptor.SourceID,
		"scope_sha256":             descriptor.ScopeSHA256,
		"plan_sha256":              descriptor.PlanSHA256,
		"inventory_sha256":         descriptor.InventorySHA256,
		"manifest_sha256":          r.ToolsManifestSHA256,
		"baseline_manifest_sha256": r.BaselineManifestSHA256,
		"candidate":                candidate,
	}, nil
}

func recoveryBrokerInspectionMatches(policy map[string]any, inspection upgradeInspection, spec map[string]any) bool {
	if len(policy) == 0 || policy["policy"] != retainPreparedControllerPolicy || policy["operation_id"] != spec["operation_id"] ||
		policy["scope_sha256"] != spec["scope_sha256"] ||
		policy["manifest_sha256"] != spec["manifest_sha256"] {
		return false
	}
	proof, _ := spec["proof"].(map[string]any)
	candidate, _ := proof["candidate"].(map[string]any)
	expected, _ := json.Marshal(candidate)
	claimed, _ := json.Marshal(policy["candidate"])
	return len(candidate) > 0 && string(expected) == string(claimed) && inspection.ControllerDirectory == candidate["directory"] &&
		inspection.ControllerUnitSHA == candidate["unit_sha256"] &&
		inspection.PreviousManifestSHA == policy["baseline_manifest_sha256"]
}

func preparedControllerRollbackIdentity(policy, spec map[string]any, inspection upgradeInspection) (string, string, error) {
	if len(policy) == 0 {
		return inspection.ControllerDirectory, inspection.ControllerUnitSHA, nil
	}
	if !recoveryBrokerInspectionMatches(policy, inspection, spec) {
		return "", "", errors.New("prepared_controller_policy_inspection_changed")
	}
	rollback := spec["proof"].(map[string]any)["rollback"].(map[string]any)
	return rollback["directory"].(string), rollback["unit_sha256"].(string), nil
}
