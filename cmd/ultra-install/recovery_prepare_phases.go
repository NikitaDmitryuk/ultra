package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

type recoveryPreparationPhaseReceipt struct {
	Protocol      string         `json:"protocol"`
	RequestSHA256 string         `json:"request_sha256"`
	Phase         string         `json:"phase"`
	StartedAt     int64          `json:"started_at"`
	Verified      bool           `json:"verified"`
	Evidence      map[string]any `json:"evidence"`
}

func preparationPhasePath(r recoveryPreparationRequest, phase, suffix string) string {
	return filepath.Join(r.StateDirectory, phase+suffix+".json")
}
func preparationPhaseKnown(phase string) bool {
	switch phase {
	case "origins_sealed", "tools_staged", "monitor_initialized", "recovery_reconciled", "readiness_verified":
		return true
	}
	return false
}
func preparationPhasePredecessor(phase string) string {
	return map[string]string{"tools_staged": "origins_sealed", "monitor_initialized": "tools_staged", "recovery_reconciled": "monitor_initialized", "readiness_verified": "recovery_reconciled"}[phase]
}

func readRecoveryPreparationPhase(r recoveryPreparationRequest, phase string) (recoveryPreparationPhaseReceipt, error) {
	var receipt recoveryPreparationPhaseReceipt
	raw, err := readRebuildInput(preparationPhasePath(r, phase, ""), true)
	if err != nil || decodeRetainedReconcile(raw, &receipt) != nil || receipt.Protocol != "ultra-recovery-preparation-phase-v1" ||
		receipt.RequestSHA256 != r.digest() ||
		receipt.Phase != phase ||
		receipt.StartedAt <= 0 ||
		!receipt.Verified {
		return receipt, errors.New("recovery_preparation_terminal_proof_unavailable")
	}
	return receipt, nil
}

// No caller may turn an interrupted started marker into a retry. Successful
// terminal proof can be observed after a supervisor crash without redispatch.
func runRecoveryPreparationPhase(ctx context.Context, phase string, r recoveryPreparationRequest, upgradeArgs []string) error {
	if !preparationPhaseKnown(phase) {
		return errors.New("recovery_preparation_phase_invalid")
	}
	if os.Geteuid() != 0 {
		return errors.New("recovery_preparation_bridge_root_required")
	}
	in, err := validateRecoveryPreparationRequest(r)
	if err != nil {
		return err
	}
	if phase != "origins_sealed" {
		if err = verifyRecoveryPreparationLegacyClosure(r); err != nil {
			return err
		}
	}
	if _, err = readRecoveryPreparationPhase(r, phase); err == nil {
		return verifyRecoveryPreparationPhase(ctx, phase, r)
	}
	retry := false
	var retainedStarted int64
	if _, err = os.Lstat(preparationPhasePath(r, phase, ".started")); !os.IsNotExist(err) {
		if recovered := recoverRecoveryPreparationTerminal(ctx, r, phase); recovered == nil {
			return verifyRecoveryPreparationPhase(ctx, phase, r)
		}
		if !recoveryPreparationRetryAuthorized(phase, upgradeArgs) {
			return errors.New("recovery_preparation_dispatch_uncertain")
		}
		retainedStarted, err = readRecoveryPreparationDispatch(r, phase)
		if err != nil {
			return err
		}
		retry = true
	}
	if previous := preparationPhasePredecessor(phase); previous != "" {
		if err = verifyRecoveryPreparationPhase(ctx, previous, r); err != nil {
			return err
		}
	}
	if err = verifyRecoveryPreparationPrimary(ctx, r, in.retained); err != nil {
		return err
	}
	if phase != "origins_sealed" {
		if err = validateRecoveryPreparationOrigins(ctx, r, in); err != nil {
			return err
		}
	}
	started := time.Now().Unix()
	if retry {
		started = retainedStarted
	}
	intent := map[string]any{
		"protocol":       "ultra-recovery-preparation-dispatch-v1",
		"request_sha256": r.digest(),
		"phase":          phase,
		"started_at":     started,
	}
	raw, _ := json.Marshal(intent)
	if err = publishRetainedReconcile(preparationPhasePath(r, phase, ".started"), raw); err != nil {
		return err
	}
	evidence := map[string]any{}
	switch phase {
	case "origins_sealed":
		if err = sealRecoveryPreparationOrigins(ctx, r, in); err != nil {
			return err
		}
		evidence["admission"] = in.admission
	case "tools_staged", "monitor_initialized":
		// All admission leases have closed before RunLocal; durable legacy origin
		// drop-ins remain blocked. The canonical execution fence covers this job.
		_, inventory, e := recoveryPreparationTransportPlan(r, in)
		if e != nil {
			return e
		}
		variables, e := recoveryPreparationGeneration(r, in)
		if e != nil {
			return e
		}
		operation := "stage-recovery-preparation"
		if phase == "monitor_initialized" {
			operation = "initialize-recovery-monitor"
		}
		payload := variables["ultra_preparation_payload"].(map[string]any)
		payload["started_at"] = started
		payload["remote_phase_receipt"] = filepath.Join("/var/lib/ultra-ansible/recovery-preparation", r.digest(), phase+".json")
		runner := deployansible.RunLocal
		executionContext := ctx
		if retry {
			runner = deployansible.RunLocalRetryFailed
			var release func()
			executionContext, release, e = deployansible.WithOperationLock(ctx, "/var/lib/ultra-ansible")
			if e != nil {
				return e
			}
			defer release()
			if e = recordRecoveryPreparationRetry(r, phase, started); e != nil {
				return e
			}
		}
		receipt, e := runner(
			executionContext,
			operation,
			inventory,
			variables,
			filepath.Join(r.StateDirectory, "ansible-"+phase),
			r.Python,
			r.Executable,
		)
		if e != nil {
			return e
		}
		if receipt.State != "succeeded" || receipt.Result.Values["verified"] != true ||
			receipt.Result.Values["request_sha256"] != r.digest() ||
			receipt.Result.Values["phase"] != phase {
			return errors.New("recovery_preparation_ansible_result_unverified")
		}
		evidence = receipt.Result.Values
	case "recovery_reconciled":
		if fence, e := deployansible.InspectExecutionFence(); e != nil || fence != nil {
			return errors.New("recovery_preparation_execution_fence_unresolved")
		}
		snapshot := filepath.Join("/opt/ultra-ansible/recovery-tools", r.ToolsManifestSHA256)
		// A direct foreground child belongs to the sole deploy supervisor. Never
		// start a second service or submit nested work from inside an Ansible job.
		command := exec.CommandContext(ctx, "/usr/bin/python3", filepath.Join(snapshot, "prepare.py"), "reconcile")
		payload, _ := json.Marshal(
			map[string]any{
				"request_sha256":       r.digest(),
				"snapshot":             snapshot,
				"started_at":           started,
				"remote_phase_receipt": filepath.Join("/var/lib/ultra-ansible/recovery-preparation", r.digest(), phase+".json"),
			},
		)
		command.Stdin = strings.NewReader(string(payload))
		if err = command.Run(); err != nil {
			return errors.New("recovery_preparation_reconcile_uncertain")
		}
		status, e := readRecoveryPreparationReadiness(ctx, r, started)
		if e != nil {
			return e
		}
		evidence = status
	case "readiness_verified":
		previous, e := readRecoveryPreparationPhase(r, "recovery_reconciled")
		if e != nil {
			return e
		}
		evidence, err = readRecoveryPreparationReadiness(ctx, r, previous.StartedAt)
		if err != nil {
			return err
		}
	}
	if err = verifyRecoveryPreparationPrimary(ctx, r, in.retained); err != nil {
		return err
	}
	if _, err = validateRecoveryPreparationRequest(r); err != nil {
		return err
	}
	terminal := recoveryPreparationPhaseReceipt{"ultra-recovery-preparation-phase-v1", r.digest(), phase, started, true, evidence}
	raw, _ = json.Marshal(terminal)
	return publishRetainedReconcile(preparationPhasePath(r, phase, ""), raw)
}

func sealRecoveryPreparationOrigins(ctx context.Context, r recoveryPreparationRequest, in recoveryPreparationInputs) error {
	if r.BridgeReimage != nil {
		return withBridgeReimageFleet(ctx, r, in, func() error { return sealRecoveryPreparationOriginsLocked(ctx, r, in) })
	}
	return sealRecoveryPreparationOriginsLocked(ctx, r, in)
}

func sealRecoveryPreparationOriginsLocked(ctx context.Context, r recoveryPreparationRequest, in recoveryPreparationInputs) error {
	p, _, err := recoveryPreparationTransportPlan(r, in)
	if err != nil {
		return err
	}
	local, err := openLocalRecoveryPreparationAdmission(ctx, in.admission, in.installers, true)
	if err != nil {
		return err
	}
	defer local.close()
	exit, err := openRecoveryPreparationAdmission(
		ctx,
		p,
		"exit",
		p.Exits[0].SSHHost,
		p.ExitSSHIdentity(p.Exits[0]),
		in.admission,
		in.installers,
		true,
	)
	if err != nil {
		return err
	}
	defer exit.close()
	if err = verifyRecoveryPreparationPrimary(ctx, r, in.retained); err != nil {
		return err
	}
	if err = local.recheck(); err != nil {
		return err
	}
	return exit.recheck()
}

func verifyRecoveryPreparationPhase(ctx context.Context, phase string, r recoveryPreparationRequest) error {
	if !preparationPhaseKnown(phase) {
		return errors.New("recovery_preparation_phase_invalid")
	}
	in, err := validateRecoveryPreparationRequest(r)
	if err != nil {
		return err
	}
	if phase != "origins_sealed" {
		if err = verifyRecoveryPreparationLegacyClosure(r); err != nil {
			return err
		}
	}
	receipt, err := readRecoveryPreparationPhase(r, phase)
	if err != nil {
		return err
	}
	if err = verifyRecoveryPreparationPrimary(ctx, r, in.retained); err != nil {
		return err
	}
	if phase == "origins_sealed" {
		// Inspection never reopens origins or treats lifecycle release as drain.
		p, _, e := recoveryPreparationTransportPlan(r, in)
		if e != nil {
			return e
		}
		local, e := openLocalRecoveryPreparationAdmission(ctx, in.admission, nil, false)
		if e != nil {
			return e
		}
		defer local.close()
		exit, e := openRecoveryPreparationAdmission(
			ctx,
			p,
			"exit",
			p.Exits[0].SSHHost,
			p.ExitSSHIdentity(p.Exits[0]),
			in.admission,
			nil,
			false,
		)
		if e != nil {
			return e
		}
		defer exit.close()
		if e = local.recheck(); e != nil {
			return e
		}
		return exit.recheck()
	}
	if phase == "tools_staged" || phase == "monitor_initialized" {
		if fence, e := deployansible.InspectExecutionFence(); e != nil || fence != nil {
			return errors.New("recovery_preparation_execution_fence_unresolved")
		}
		remote := filepath.Join("/var/lib/ultra-ansible/recovery-preparation", r.digest(), phase+".json")
		raw, e := readRebuildInput(remote, true)
		if e != nil {
			return errors.New("recovery_preparation_remote_proof_unavailable")
		}
		var proof map[string]any
		if decodeRetainedReconcile(raw, &proof) != nil || proof["request_sha256"] != r.digest() || proof["phase"] != phase ||
			proof["verified"] != true {
			return errors.New("recovery_preparation_remote_proof_changed")
		}
		return verifyRecoveryPreparationInstalled(r, phase)
	}
	notBefore := receipt.StartedAt
	if phase == "readiness_verified" {
		previous, e := readRecoveryPreparationPhase(r, "recovery_reconciled")
		if e != nil {
			return e
		}
		notBefore = previous.StartedAt
	}
	_, err = readRecoveryPreparationReadiness(ctx, r, notBefore)
	return err
}

func readRecoveryPreparationReadiness(ctx context.Context, r recoveryPreparationRequest, notBefore int64) (map[string]any, error) {
	snapshot := filepath.Join("/opt/ultra-ansible/recovery-tools", r.ToolsManifestSHA256)
	output, err := exec.CommandContext(ctx, "/usr/bin/python3", filepath.Join(snapshot, "recovery/recovery_status.py"), "--not-before", fmt.Sprint(notBefore)).
		Output()
	if err != nil {
		return nil, errors.New("recovery_preparation_fresh_independent_readiness_required")
	}
	return validateRecoveryPreparationReadiness(output)
}

func validateRecoveryPreparationReadiness(output []byte) (map[string]any, error) {
	var result map[string]any
	if len(output) > 16384 || decodeRetainedReconcile(output, &result) != nil || result["verified"] != true || result["ready"] != true ||
		result["independent"] != true {
		return nil, errors.New("recovery_preparation_fresh_independent_readiness_required")
	}
	reasons, ok := result["reasons"].([]any)
	if !ok || len(reasons) != 0 {
		return nil, errors.New("recovery_preparation_readiness_reasons_nonempty")
	}
	return result, nil
}

func verifyRecoveryPreparationInstalled(r recoveryPreparationRequest, phase string) error {
	for _, path := range []string{"/opt/ultra-recovery/release-manifest.json", "/usr/local/libexec/ultra-emergency-manifest.json", "/var/lib/ultra-automation/release-manifest.json"} {
		raw, err := readRebuildInput(path, true)
		if err != nil || digestSHA256(raw) != r.BaselineManifestSHA256 {
			return errors.New("recovery_preparation_application_baseline_changed")
		}
	}
	raw, err := readRebuildInput("/etc/ultra-recovery/recovery-tools.json", true)
	var identity map[string]any
	if err != nil || decodeRetainedReconcile(raw, &identity) != nil || identity["request_sha256"] != r.digest() ||
		identity["tools_manifest_sha256"] != r.ToolsManifestSHA256 ||
		identity["baseline_manifest_sha256"] != r.BaselineManifestSHA256 {
		return errors.New("recovery_preparation_tools_identity_changed")
	}
	suspensionRaw, err := readRebuildInput("/etc/ultra-recovery/preparation-suspension.json", true)
	var suspension struct {
		Protocol  string            `json:"protocol"`
		Request   string            `json:"request_sha256"`
		Tools     string            `json:"tools_manifest_sha256"`
		Inventory map[string]string `json:"active_inventory"`
		Gate      string            `json:"background_gate_sha256"`
	}
	if err != nil || json.Unmarshal(suspensionRaw, &suspension) != nil ||
		suspension.Protocol != "ultra-recovery-preparation-suspension-v1" ||
		suspension.Request != r.digest() ||
		suspension.Tools != r.ToolsManifestSHA256 ||
		len(suspension.Inventory) == 0 ||
		!runtimeHostValidDigest(suspension.Gate) {
		return errors.New("recovery_preparation_active_runtime_unverified")
	}
	for path, sha := range suspension.Inventory {
		if (!strings.HasPrefix(path, "/opt/ultra-recovery/") && !strings.HasPrefix(path, "/etc/systemd/system/")) ||
			!runtimeHostValidDigest(sha) {
			return errors.New("recovery_preparation_active_runtime_unverified")
		}
		actual, e := sourceSHA(path)
		if e != nil || actual != sha {
			return errors.New("recovery_preparation_active_runtime_unverified")
		}
	}
	for _, name := range []string{"ultra-recovery-backup.service", "ultra-recovery-reconcile.service"} {
		actual, e := sourceSHA(filepath.Join("/etc/systemd/system", name+".d", "95-deployment-background.conf"))
		if e != nil || actual != suspension.Gate {
			return errors.New("recovery_preparation_background_gate_unverified")
		}
	}
	inventory, ok := identity["inventory"].(map[string]any)
	if !ok || len(inventory) == 0 {
		return errors.New("recovery_preparation_tools_inventory_missing")
	}
	snapshot := filepath.Join("/opt/ultra-ansible/recovery-tools", r.ToolsManifestSHA256)
	seen := 0
	err = filepath.WalkDir(snapshot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("recovery_preparation_tools_symlink")
		}
		if entry.IsDir() {
			return nil
		}
		rel, e := filepath.Rel(snapshot, path)
		if e != nil {
			return e
		}
		expected, ok := inventory[filepath.ToSlash(rel)].(string)
		if !ok || !runtimeHostValidDigest(expected) {
			return errors.New("recovery_preparation_tools_inventory_changed")
		}
		actual, e := sourceSHA(path)
		if e != nil || actual != expected {
			return errors.New("recovery_preparation_tools_file_changed")
		}
		seen++
		return nil
	})
	if err != nil {
		return err
	}
	if seen != len(inventory) {
		return errors.New("recovery_preparation_tools_inventory_incomplete")
	}
	if phase == "monitor_initialized" {
		for _, path := range []string{"/etc/ultra-recovery/probe.json", "/etc/ultra-recovery/admin-chat-id"} {
			if _, err = readRebuildInput(path, true); err != nil {
				return errors.New("recovery_preparation_monitor_proof_missing")
			}
		}
	}
	manifestRaw, e := readRebuildInput(filepath.Join(r.ToolsReleaseDirectory, "release-manifest.json"), false)
	if e != nil {
		return e
	}
	var manifest automationRelease
	if json.Unmarshal(manifestRaw, &manifest) != nil {
		return errors.New("recovery_preparation_tools_manifest_invalid")
	}
	installer, e := upgradeAsset(&manifest, "ultra-install-linux-"+runtime.GOARCH)
	if e != nil {
		return e
	}
	runtimeAsset, e := upgradeAsset(&manifest, "ultra-ansible-runtime-linux-"+runtime.GOARCH+".tar.gz")
	if e != nil {
		return e
	}
	controller := managedControllerDirectory(manifest.Version)
	actual, e := sourceSHA(filepath.Join(controller, "ultra-install"))
	if e != nil || actual != installer.SHA ||
		!installedRuntimeMatches(
			filepath.Join(controller, "venv/bin/ansible-playbook"),
			filepath.Join(controller, "runtime.sha256"),
			runtimeAsset.SHA,
		) {
		return errors.New("recovery_preparation_candidate_runtime_changed")
	}
	return nil
}

// Recover only exact terminal evidence after a crash between completion and the
// supervisor checkpoint. An absent/failed child or a free PID/flock is not proof.
func recoverRecoveryPreparationTerminal(ctx context.Context, r recoveryPreparationRequest, phase string) error {
	raw, err := readRebuildInput(preparationPhasePath(r, phase, ".started"), true)
	var intent struct {
		Protocol   string `json:"protocol"`
		RequestSHA string `json:"request_sha256"`
		Phase      string `json:"phase"`
		StartedAt  int64  `json:"started_at"`
	}
	if err != nil || decodeRetainedReconcile(raw, &intent) != nil || intent.Protocol != "ultra-recovery-preparation-dispatch-v1" ||
		intent.RequestSHA != r.digest() ||
		intent.Phase != phase ||
		intent.StartedAt <= 0 {
		return errors.New("recovery_preparation_dispatch_uncertain")
	}
	if fence, e := deployansible.InspectExecutionFence(); e != nil || fence != nil {
		return errors.New("recovery_preparation_execution_fence_unresolved")
	}
	evidence := map[string]any{}
	switch phase {
	case "origins_sealed":
		in, e := validateRecoveryPreparationRequest(r)
		if e != nil {
			return e
		}
		if e = verifyRecoveryPreparationPrimary(ctx, r, in.retained); e != nil {
			return e
		}
		if e = validateRecoveryPreparationOrigins(ctx, r, in); e != nil {
			return e
		}
		evidence["admission"] = in.admission
	case "readiness_verified":
		previous, e := readRecoveryPreparationPhase(r, "recovery_reconciled")
		if e != nil {
			return e
		}
		evidence, err = readRecoveryPreparationReadiness(ctx, r, previous.StartedAt)
		if err != nil {
			return err
		}
	default:
		path := filepath.Join("/var/lib/ultra-ansible/recovery-preparation", r.digest(), phase+".json")
		raw, err = readRebuildInput(path, true)
		if err != nil || decodeRetainedReconcile(raw, &evidence) != nil ||
			evidence["protocol"] != "ultra-recovery-preparation-terminal-v1" ||
			evidence["request_sha256"] != r.digest() ||
			evidence["phase"] != phase ||
			evidence["verified"] != true ||
			evidence["started_at"] != json.Number(fmt.Sprint(intent.StartedAt)) {
			return errors.New("recovery_preparation_dispatch_uncertain")
		}
		switch phase {
		case "tools_staged", "monitor_initialized":
			raw, err = readRebuildInput(filepath.Join(r.StateDirectory, "ansible-"+phase, "receipt.json"), true)
			var saved map[string]any
			if err != nil || decodeRetainedReconcile(raw, &saved) != nil || saved["state"] != "succeeded" {
				return errors.New("recovery_preparation_ansible_completion_unproven")
			}
			result, ok := saved["result"].(map[string]any)
			if !ok || result["request_sha256"] != r.digest() || result["phase"] != phase || result["verified"] != true {
				return errors.New("recovery_preparation_ansible_completion_unproven")
			}
			if err = verifyRecoveryPreparationInstalled(r, phase); err != nil {
				return err
			}
		case "recovery_reconciled":
			if _, err = readRecoveryPreparationReadiness(ctx, r, intent.StartedAt); err != nil {
				return err
			}
		}
	}
	terminal := recoveryPreparationPhaseReceipt{"ultra-recovery-preparation-phase-v1", r.digest(), phase, intent.StartedAt, true, evidence}
	raw, _ = json.Marshal(terminal)
	return publishRetainedReconcile(preparationPhasePath(r, phase, ""), raw)
}

func validateRecoveryPreparationOrigins(ctx context.Context, r recoveryPreparationRequest, in recoveryPreparationInputs) error {
	p, _, err := recoveryPreparationTransportPlan(r, in)
	if err != nil {
		return err
	}
	local, err := openLocalRecoveryPreparationAdmission(ctx, in.admission, nil, false)
	if err != nil {
		return err
	}
	defer local.close()
	exit, err := openRecoveryPreparationAdmission(
		ctx,
		p,
		"exit",
		p.Exits[0].SSHHost,
		p.ExitSSHIdentity(p.Exits[0]),
		in.admission,
		nil,
		false,
	)
	if err != nil {
		return err
	}
	defer exit.close()
	if err = local.recheck(); err != nil {
		return err
	}
	return exit.recheck()
}

func recoveryPreparationRetryAuthorized(phase string, args []string) bool {
	if phase != "tools_staged" && phase != "monitor_initialized" {
		return false
	}
	count := 0
	enabled := false
	for _, arg := range args {
		switch arg {
		case "--retry-failed", "--retry-failed=true":
			count++
			enabled = true
		case "--retry-failed=false":
			count++
			enabled = false
		}
	}
	return count == 1 && enabled
}

func readRecoveryPreparationDispatch(r recoveryPreparationRequest, phase string) (int64, error) {
	raw, err := readRebuildInput(preparationPhasePath(r, phase, ".started"), true)
	var saved struct {
		Protocol string `json:"protocol"`
		Request  string `json:"request_sha256"`
		Phase    string `json:"phase"`
		Started  int64  `json:"started_at"`
	}
	if err != nil || decodeRetainedReconcile(raw, &saved) != nil || saved.Protocol != "ultra-recovery-preparation-dispatch-v1" ||
		saved.Request != r.digest() ||
		saved.Phase != phase ||
		saved.Started <= 0 {
		return 0, errors.New("recovery_preparation_dispatch_binding_changed")
	}
	return saved.Started, nil
}

func recordRecoveryPreparationRetry(r recoveryPreparationRequest, phase string, started int64) error {
	// This descriptor records intent only. The canonical runner independently
	// verifies normal terminal callback/cleanup before advancing an attempt.
	path := filepath.Join(r.StateDirectory, "ansible-"+phase, "job.json")
	raw, err := readRebuildInput(path, true)
	var job struct {
		Operation string `json:"operation"`
		Attempt   int    `json:"attempt"`
		Request   string `json:"request_sha256"`
	}
	if err != nil || json.Unmarshal(raw, &job) != nil || !runtimeHostValidDigest(job.Request) {
		return errors.New("recovery_preparation_retry_frozen_job_required")
	}
	descriptor := map[string]any{
		"protocol":            "ultra-recovery-preparation-retry-v1",
		"request_sha256":      r.digest(),
		"phase":               phase,
		"original_started_at": started,
		"job_sha256":          digestSHA256(raw),
		"job_request_sha256":  job.Request,
		"from_attempt":        job.Attempt,
	}
	encoded, _ := json.Marshal(descriptor)
	return publishRetainedReconcile(preparationPhasePath(r, phase, fmt.Sprintf(".retry-%d", job.Attempt)), encoded)
}
