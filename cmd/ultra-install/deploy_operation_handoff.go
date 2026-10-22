package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	ansibleassets "github.com/NikitaDmitryuk/ultra/deploy/ansible"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
	"github.com/google/uuid"
)

type recoveryBrokerPlan struct {
	plan            *installplan.InstallPlan
	manifest        *automationRelease
	directory, lock string
	inventory       map[string]any
	spec            map[string]any
}

type recoveryBrokerPreflight struct {
	Protocol          string `json:"protocol"`
	RequestSHA256     string `json:"request_sha256"`
	Directory         string `json:"directory"`
	OperationID       string `json:"operation_id"`
	SourceID          string `json:"source_id"`
	ScopeSHA256       string `json:"scope_sha256"`
	InventorySHA256   string `json:"inventory_sha256"`
	PlanSHA256        string `json:"plan_sha256"`
	EnforcementSHA256 string `json:"enforcement_sha256"`
}

func recoveryUpgradePlan(r recoveryPreparationRequest, args []string) (recoveryBrokerPlan, error) {
	return recoveryUpgradePlanWithMode(r, args, true)
}

func recoveryUpgradePlanWithMode(r recoveryPreparationRequest, args []string, freeze bool) (recoveryBrokerPlan, error) {
	var result recoveryBrokerPlan
	if len(args) == 0 || args[0] != "operator-upgrade" {
		return result, errors.New("recovery_broker_upgrade_arguments_invalid")
	}
	fs := flag.NewFlagSet("recovery-broker-upgrade", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	config := fs.String("config", "", "")
	release := fs.String("release-dir", "", "")
	commit := fs.String("source-commit", "", "")
	version := fs.String("version", "", "")
	manifestSHA := fs.String("manifest-sha256", "", "")
	configSHA := fs.String("config-sha256", "", "")
	directory := fs.String("job-dir", "", "")
	source := fs.String("secrets-source", "installed-runtime", "")
	forward := fs.Bool("forward-only", false, "")
	fs.Bool("retry-failed", false, "")
	fs.Bool("lifecycle", false, "")
	fs.String("subscription-probe-url-file", "", "")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || *forward || *source != "installed-runtime" || *config != r.UpgradeConfigPath ||
		*release != r.ToolsReleaseDirectory ||
		*manifestSHA != r.ToolsManifestSHA256 ||
		*configSHA != r.UpgradeConfigSHA256 {
		return result, errors.New("recovery_broker_upgrade_binding_changed")
	}
	manifest, err := verifyAutomationRelease(*release, *version)
	if err != nil || manifest.SourceCommit != *commit {
		return result, errors.New("recovery_broker_release_changed")
	}
	p, err := installplan.LoadLifecycleConfig(*config)
	if err != nil || installplan.ValidatePlan(p) != nil || !localLifecycleMachineIdentity(p) {
		return result, errors.New("recovery_broker_local_plan_required")
	}
	if err = selectPlanSecrets(p, "installed-runtime"); err != nil {
		return result, err
	}
	if *directory == "" {
		*directory = filepath.Join("/var/lib/ultra-ansible", "upgrade-"+manifest.Version)
	}
	if !filepath.IsAbs(*directory) || filepath.Clean(*directory) != *directory || filepath.Dir(*directory) != "/var/lib/ultra-ansible" {
		return result, errors.New("recovery_broker_canonical_upgrade_directory_required")
	}
	if freeze {
		if err = ensurePrivateBootstrapDirectory(*directory); err != nil {
			return result, err
		}
		if err = freezeOperatorPlan(*directory, p, *release); err != nil {
			return result, err
		}
	} else {
		if err = operatorPrivate(*directory, true); err != nil {
			return result, err
		}
		if err = matchOperatorPlan(*directory, p, *release); err != nil {
			return result, err
		}
	}
	lock := "/var/lib/ultra-ansible"
	if !freeze {
		raw, e := readRebuildInput(filepath.Join(*directory, "execution-mode.json"), true)
		var mode frozenExecution
		if e != nil || json.Unmarshal(raw, &mode) != nil || mode.Schema != 1 || !mode.Local || mode.Native || mode.LockDirectory != lock ||
			mode.Target != p.Bridge.SSHHost+"|"+p.Bridge.Address {
			return result, errors.New("recovery_broker_execution_mode_changed")
		}
	} else {
		lock, err = freezeBootstrapExecution(p, *directory, filepath.Dir(*directory))
	}
	if err != nil || lock != "/var/lib/ultra-ansible" {
		return result, errors.New("recovery_broker_execution_mode_changed")
	}
	inventory, err := upgradeInventory(p, *directory)
	if err != nil {
		return result, err
	}
	raw, _ := json.Marshal(inventory)
	if freeze {
		err = writeUpgradeInput(filepath.Join(*directory, "recovery-upgrade-inventory.json"), raw)
	} else {
		saved, e := readRebuildInput(filepath.Join(*directory, "recovery-upgrade-inventory.json"), true)
		if e != nil || string(saved) != string(raw) {
			err = errors.New("recovery_broker_inventory_changed")
		}
	}
	if err != nil {
		return result, err
	}
	spec, err := upgradeEnforcementSpec(*directory, *release, manifest, inventory)
	if err != nil {
		return result, err
	}
	return recoveryBrokerPlan{p, manifest, *directory, lock, inventory, spec}, nil
}

func runRecoveryBrokerPreflight(ctx context.Context, r recoveryPreparationRequest, args []string) error {
	if err := requireRecoveryBrokerSupervisor(r); err != nil {
		return err
	}
	in, err := validateRecoveryPreparationRequest(r)
	if err != nil {
		return err
	}
	if err = verifyRecoveryPreparationLegacyClosure(r); err != nil {
		return err
	}
	if _, err = os.Lstat(filepath.Join(r.StateDirectory, "broker-preflight.json")); err == nil {
		return verifyRecoveryBrokerPreflight(ctx, r, args)
	}
	if err = validateRecoveryPreparationOrigins(ctx, r, in); err != nil {
		return err
	}
	plan, err := recoveryUpgradePlan(r, args)
	if err != nil {
		return err
	}
	operator, releaseOperator, err := withBootstrapOperatorLock(ctx, filepath.Dir(plan.directory))
	if err != nil {
		return err
	}
	defer releaseOperator()
	locked, release, err := deployansible.WithOperationLock(operator, plan.lock)
	if err != nil {
		return err
	}
	defer release()
	lifecycle, err := readRecoveryBrokerLifecycle(plan.lock)
	if err != nil || lifecycle.Phase != "released" {
		return errors.New("recovery_broker_released_source_required")
	}
	if err = observeRecoveryBrokerEnforcement(locked, r, plan, "preflight", true); err != nil {
		return err
	}
	proof, _ := plan.spec["proof"].(map[string]any)
	if len(proof) == 0 {
		return errors.New("recovery_broker_enforcement_floor_initialization_required")
	}
	source, _ := proof["source_lifecycle"].(map[string]any)
	if source["id"] != lifecycle.ID {
		return errors.New("recovery_broker_source_lifecycle_changed")
	}
	descriptor, err := recoveryBrokerDescriptor(r, plan)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(descriptor)
	return publishRetainedReconcile(filepath.Join(r.StateDirectory, "broker-preflight.json"), raw)
}

func recoveryBrokerDescriptor(r recoveryPreparationRequest, plan recoveryBrokerPlan) (recoveryBrokerPreflight, error) {
	var result recoveryBrokerPreflight
	proof, _ := plan.spec["proof"].(map[string]any)
	if validateEnforcementProof(proof, plan.spec) != nil {
		return result, errors.New("recovery_broker_enforcement_proof_unverified")
	}
	source := proof["source_lifecycle"].(map[string]any)
	inventory, _ := json.Marshal(plan.inventory)
	planSHA, err := sourceSHA(filepath.Join(plan.directory, "operator-plan.json"))
	if err != nil {
		return result, err
	}
	enforcementSHA, err := sourceSHA(filepath.Join(plan.directory, enforcementProofFile))
	if err != nil {
		return result, err
	}
	return recoveryBrokerPreflight{
		"ultra-recovery-broker-preflight-v1",
		r.digest(),
		plan.directory,
		lifecycleID(plan.directory),
		source["id"].(string),
		plan.spec["scope_sha256"].(string),
		digestSHA256(inventory),
		planSHA,
		enforcementSHA,
	}, nil
}

func readRecoveryBrokerPreflight(r recoveryPreparationRequest, plan recoveryBrokerPlan) (recoveryBrokerPreflight, error) {
	var saved recoveryBrokerPreflight
	raw, err := readRebuildInput(filepath.Join(r.StateDirectory, "broker-preflight.json"), true)
	expected, e := recoveryBrokerDescriptor(r, plan)
	if err != nil || e != nil || decodeRetainedReconcile(raw, &saved) != nil || saved != expected {
		return saved, errors.New("recovery_broker_preflight_binding_changed")
	}
	return saved, nil
}

func verifyRecoveryBrokerPreflight(ctx context.Context, r recoveryPreparationRequest, args []string) error {
	if _, err := validateRecoveryPreparationRequest(r); err != nil {
		return err
	}
	if err := verifyRecoveryPreparationLegacyClosure(r); err != nil {
		return err
	}
	plan, err := recoveryUpgradePlanWithMode(r, args, false)
	if err != nil {
		return err
	}
	if _, err = readRecoveryBrokerPreflight(r, plan); err != nil {
		return err
	}
	// The existing verifier permits only the bound released source or same planned
	// applying lifecycle. It always rechecks the exact immutable ledger/runtime.
	return observeRecoveryBrokerProof(ctx, r, plan, false)
}

func observeRecoveryBrokerEnforcement(
	ctx context.Context,
	r recoveryPreparationRequest,
	plan recoveryBrokerPlan,
	phase string,
	recovery bool,
) error {
	spec := map[string]any{}
	for key, value := range plan.spec {
		spec[key] = value
	}
	spec["phase"] = phase
	stage, err := os.MkdirTemp(plan.directory, "recovery-controller-preflight-")
	if err != nil {
		return err
	}
	if err = os.Remove(stage); err != nil {
		return err
	}
	variables := map[string]any{
		"ultra_lock_directory":                        plan.lock,
		"ultra_controller_enforcement_preflight_only": true,
		"ultra_controller_enforcement_spec":           spec,
	}
	if recovery {
		variables["ultra_recovery_preparation_request_sha256"] = r.digest()
	}
	receipt, err := deployansible.RunLocal(ctx, "inspect-upgrade", plan.inventory, variables, stage, r.Python, r.Executable)
	if err != nil {
		return err
	}
	proof, ok := receipt.Result.Values["controller_enforcement_proof"].(map[string]any)
	if receipt.Result.Values["verified"] != true || !ok || validateEnforcementProof(proof, spec) != nil {
		return errors.New("recovery_broker_enforcement_floor_initialization_required")
	}
	raw, _ := json.Marshal(proof)
	if err = writeUpgradeInput(filepath.Join(plan.directory, enforcementProofFile), raw); err != nil {
		return err
	}
	plan.spec["proof"] = proof
	return nil
}

type recoveryBrokerLifecycle struct {
	ID    string `json:"id"`
	Phase string `json:"phase"`
}

func readRecoveryBrokerLifecycle(root string) (recoveryBrokerLifecycle, error) {
	var state recoveryBrokerLifecycle
	raw, err := readRebuildInput(filepath.Join(root, "lifecycle.json"), true)
	if err != nil || decodeRetainedReconcile(raw, &state) != nil {
		return state, errors.New("recovery_broker_lifecycle_invalid")
	}
	parsed, e := uuid.Parse(state.ID)
	if e != nil || parsed.String() != state.ID || (state.Phase != "released" && state.Phase != "applying" && state.Phase != "checking") {
		return state, errors.New("recovery_broker_lifecycle_invalid")
	}
	return state, nil
}

func runRecoveryBrokerHandoff(ctx context.Context, r recoveryPreparationRequest, args []string) error {
	if err := requireRecoveryBrokerSupervisor(r); err != nil {
		return err
	}
	in, err := validateRecoveryPreparationRequest(r)
	if err != nil {
		return err
	}
	if err = verifyRecoveryPreparationLegacyClosure(r); err != nil {
		return err
	}
	plan, err := recoveryUpgradePlan(r, args)
	if err != nil {
		return err
	}
	descriptor, err := readRecoveryBrokerPreflight(r, plan)
	if err != nil {
		return err
	}
	if _, err = os.Lstat(filepath.Join(r.StateDirectory, "broker-handoff.json")); err == nil {
		return verifyRecoveryBrokerHandoff(ctx, r, args)
	}
	job := filepath.Join(r.StateDirectory, "ansible-broker-handoff")
	if fence, e := deployansible.InspectExecutionFence(); e != nil {
		return e
	} else if fence != nil {
		if fence.JobDirectory != job {
			return deployansible.ErrExecutionFenced
		}
		if e = deployansible.ReconcileExecutionFence(*fence); e != nil {
			return e
		}
	}
	lifecycle, err := readRecoveryBrokerLifecycle(plan.lock)
	if err != nil {
		return err
	}
	initial := lifecycle.ID == descriptor.SourceID && lifecycle.Phase == "released"
	if initial {
		if err = verifyRecoveryPreparationPhase(ctx, "readiness_verified", r); err != nil {
			return err
		}
		// All three admission leases close before taking the handoff OFD.
		if err = validateRecoveryPreparationOrigins(ctx, r, in); err != nil {
			return err
		}
	} else if lifecycle.ID != descriptor.OperationID || (lifecycle.Phase != "applying" && lifecycle.Phase != "checking") {
		return errors.New("recovery_broker_lifecycle_changed")
	}
	operator, releaseOperator, err := withBootstrapOperatorLock(ctx, filepath.Dir(plan.directory))
	if err != nil {
		return err
	}
	defer releaseOperator()
	client := deployansible.Client{Socket: lifecycleSocket()}
	locked, release, err := client.WithLifecycleOperationLock(operator, plan.lock, descriptor.OperationID)
	if err != nil {
		return err
	}
	defer release()
	if err = deployansible.ReservePreparedLifecycle(locked, plan.lock, descriptor.SourceID, descriptor.OperationID, r.digest()); err != nil {
		return err
	}
	variables, err := recoveryBrokerVariables(r, plan)
	if err != nil {
		return err
	}
	// No failed/ambiguous handoff is redispatched. A cached successful exact job
	// may finish only the descriptor handshake and exact drop-in retirement.
	if _, err = os.Lstat(filepath.Join(job, "job.json")); err == nil {
		if err = verifyRecoveryBrokerJob(r, job); err != nil {
			return err
		}
	} else if os.IsNotExist(err) {
		receipt, e := deployansible.RunLocal(locked, "handoff-recovery-controller", plan.inventory, variables, job, r.Python, r.Executable)
		if e != nil {
			return e
		}
		if receipt.Result.Values["verified"] != true || receipt.Result.Values["request_sha256"] != r.digest() {
			return errors.New("recovery_broker_handoff_unverified")
		}
	} else {
		return err
	}
	return finishRecoveryBrokerMetadata(ctx, locked, r, in, plan, descriptor, client)
}

func finishRecoveryBrokerMetadata(
	ctx, locked context.Context,
	r recoveryPreparationRequest,
	in recoveryPreparationInputs,
	plan recoveryBrokerPlan,
	descriptor recoveryBrokerPreflight,
	client deployansible.Client,
) error {
	before, err := observeRecoveryBrokerInstance(ctx, plan)
	if err != nil {
		return err
	}
	if err = client.ResumeLifecycleWithOperationLock(locked, descriptor.OperationID); err != nil {
		return err
	}
	after, err := observeRecoveryBrokerInstance(ctx, plan)
	if err != nil || after != before {
		return errors.New("recovery_broker_instance_changed_during_handshake")
	}
	acknowledgement := map[string]any{
		"protocol":       "ultra-recovery-broker-ack-v1",
		"request_sha256": r.digest(),
		"operation_id":   descriptor.OperationID,
		"scope_sha256":   descriptor.ScopeSHA256,
		"instance":       after,
	}
	raw, _ := json.Marshal(acknowledgement)
	ackPath := filepath.Join(r.StateDirectory, "broker-handoff-ack-"+after.PID+"-"+after.StartTime+".json")
	if err = publishRetainedReconcile(ackPath, raw); err != nil {
		return err
	}
	if err = retireRecoveryBrokerDropin(ctx, r, plan); err != nil {
		return err
	}
	if err = observeRecoveryBrokerProof(ctx, r, plan, true); err != nil {
		return err
	}
	if err = verifyRecoveryPreparationPrimary(ctx, r, in.retained); err != nil {
		return err
	}
	raw, _ = json.Marshal(
		map[string]any{
			"protocol":        "ultra-recovery-broker-handoff-v1",
			"request_sha256":  r.digest(),
			"preflight":       descriptor,
			"verified":        true,
			"acknowledgement": filepath.Base(ackPath),
		},
	)
	return publishRetainedReconcile(filepath.Join(r.StateDirectory, "broker-handoff.json"), raw)
}

func recoveryBrokerVariables(r recoveryPreparationRequest, plan recoveryBrokerPlan) (map[string]any, error) {
	directory, variables, err := recoveryPreparationControllerGeneration(r)
	if err != nil {
		return nil, err
	}
	proof := plan.spec["proof"].(map[string]any)
	rollback := proof["rollback"].(map[string]any)
	candidate := proof["candidate"].(map[string]any)
	if candidate["directory"] != directory {
		return nil, errors.New("recovery_broker_candidate_changed")
	}
	for k, v := range map[string]any{"ultra_lock_directory": plan.lock, "ultra_lifecycle_id": lifecycleID(plan.directory), "ultra_release_version": plan.manifest.Version, "ultra_release_manifest_sha256": r.ToolsManifestSHA256, "ultra_architecture": candidate["architecture"], "ultra_previous_controller_directory": rollback["directory"], "ultra_previous_controller_unit_sha256": rollback["unit_sha256"], "ultra_target_controller_unit_sha256": candidate["unit_sha256"], "ultra_controller_enforcement_spec": plan.spec, "ultra_recovery_preparation_request_sha256": r.digest(), "ultra_recovery_controller_authorization": map[string]any{"protocol": "ultra-recovery-controller-handoff-v1", "request_sha256": r.digest(), "operation_id": lifecycleID(plan.directory), "candidate": candidate}} {
		variables[k] = v
	}
	return variables, nil
}

func verifyRecoveryBrokerJob(r recoveryPreparationRequest, job string) error {
	fail := errors.New("recovery_broker_handoff_dispatch_uncertain")
	raw, err := readRebuildInput(filepath.Join(job, "receipt.json"), true)
	var receipt map[string]any
	if err != nil || decodeRetainedReconcile(raw, &receipt) != nil || receipt["state"] != "succeeded" {
		return fail
	}
	result, ok := receipt["result"].(map[string]any)
	if !ok || result["verified"] != true || result["request_sha256"] != r.digest() {
		return fail
	}
	request, e := readRebuildInput(filepath.Join(job, "request.json"), true)
	if e != nil {
		return fail
	}
	jobRaw, e := readRebuildInput(filepath.Join(job, "job.json"), true)
	var metadata map[string]any
	if e != nil || decodeRetainedReconcile(jobRaw, &metadata) != nil || metadata["operation"] != "handoff-recovery-controller" ||
		metadata["request_sha256"] != digestSHA256(request) ||
		receipt["request_sha256"] != metadata["request_sha256"] ||
		receipt["binary_sha256"] != metadata["binary_sha256"] {
		return fail
	}
	completeRaw, e := readRebuildInput(filepath.Join(job, "execution-completion.json"), true)
	var complete struct {
		Fence       deployansible.ExecutionFence `json:"fence"`
		Cleanup     bool                         `json:"local_cleanup"`
		Outcome     string                       `json:"outcome"`
		TerminalSHA string                       `json:"terminal_sha256"`
		ReceiptSHA  string                       `json:"receipt_sha256"`
	}
	if e != nil || decodeRetainedReconcile(completeRaw, &complete) != nil || !complete.Cleanup || complete.Outcome != "succeeded" ||
		complete.ReceiptSHA != digestSHA256(raw) ||
		complete.Fence.JobDirectory != job ||
		complete.Fence.Operation != "handoff-recovery-controller" ||
		complete.Fence.RequestSHA256 != digestSHA256(request) ||
		complete.Fence.JobSHA256 != digestSHA256(jobRaw) {
		return fail
	}
	return nil
}

func recoveryBrokerDropinRetired() bool {
	_, err := os.Lstat("/etc/systemd/system/ultra-ansible-controller.service.d/90-retained-primary.conf")
	return os.IsNotExist(err)
}

func verifyRecoveryBrokerHandoff(ctx context.Context, r recoveryPreparationRequest, args []string) error {
	if _, err := validateRecoveryPreparationRequest(r); err != nil {
		return err
	}
	if err := verifyRecoveryPreparationLegacyClosure(r); err != nil {
		return err
	}
	plan, err := recoveryUpgradePlanWithMode(r, args, false)
	if err != nil {
		return err
	}
	descriptor, err := readRecoveryBrokerPreflight(r, plan)
	if err != nil {
		return err
	}
	raw, err := readRebuildInput(filepath.Join(r.StateDirectory, "broker-handoff.json"), true)
	var terminal struct {
		Protocol        string                  `json:"protocol"`
		Request         string                  `json:"request_sha256"`
		Preflight       recoveryBrokerPreflight `json:"preflight"`
		Verified        bool                    `json:"verified"`
		Acknowledgement string                  `json:"acknowledgement"`
	}
	if err != nil || decodeRetainedReconcile(raw, &terminal) != nil || terminal.Protocol != "ultra-recovery-broker-handoff-v1" ||
		terminal.Request != r.digest() ||
		terminal.Preflight != descriptor ||
		!terminal.Verified ||
		!recoveryBrokerDropinRetired() {
		return errors.New("recovery_broker_terminal_proof_unverified")
	}
	if terminal.Acknowledgement == "" || filepath.Base(terminal.Acknowledgement) != terminal.Acknowledgement ||
		!strings.HasPrefix(terminal.Acknowledgement, "broker-handoff-ack-") {
		return errors.New("recovery_broker_acknowledgement_missing")
	}
	ackRaw, e := readRebuildInput(filepath.Join(r.StateDirectory, terminal.Acknowledgement), true)
	var ack struct {
		Protocol  string                 `json:"protocol"`
		Request   string                 `json:"request_sha256"`
		Operation string                 `json:"operation_id"`
		Scope     string                 `json:"scope_sha256"`
		Instance  recoveryBrokerInstance `json:"instance"`
	}
	if e != nil || decodeRetainedReconcile(ackRaw, &ack) != nil || ack.Protocol != "ultra-recovery-broker-ack-v1" ||
		ack.Request != r.digest() ||
		ack.Operation != descriptor.OperationID ||
		ack.Scope != descriptor.ScopeSHA256 ||
		ack.Instance.PID == "" ||
		ack.Instance.StartTime == "" {
		return errors.New("recovery_broker_acknowledgement_changed")
	}
	if err = verifyRecoveryBrokerJob(r, filepath.Join(r.StateDirectory, "ansible-broker-handoff")); err != nil {
		return err
	}
	lifecycle, err := readRecoveryBrokerLifecycle(plan.lock)
	if err != nil || lifecycle.ID != descriptor.OperationID || (lifecycle.Phase != "applying" && lifecycle.Phase != "checking") {
		return errors.New("recovery_broker_lifecycle_changed")
	}
	instance, instanceErr := observeRecoveryBrokerInstance(ctx, plan)
	if instanceErr != nil || instance != ack.Instance {
		return errors.New("recovery_broker_acknowledged_instance_changed")
	}
	if err = (deployansible.Client{Socket: lifecycleSocket()}).ObserveLifecycleOperationLock(ctx, plan.lock, descriptor.OperationID); err != nil {
		return err
	}
	return observeRecoveryBrokerProof(ctx, r, plan, true)
}

func retireRecoveryBrokerDropin(ctx context.Context, r recoveryPreparationRequest, plan recoveryBrokerPlan) error {
	candidate := plan.spec["proof"].(map[string]any)["candidate"]
	raw, _ := json.Marshal(
		map[string]any{
			"protocol":       "ultra-recovery-controller-handoff-v1",
			"request_sha256": r.digest(),
			"operation_id":   lifecycleID(plan.directory),
			"candidate":      candidate,
		},
	)
	command := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-c", recoveryBrokerRetireProgram, string(raw))
	if command.Run() != nil {
		return errors.New("recovery_broker_admission_retirement_unverified")
	}
	return nil
}

const recoveryBrokerRetireProgram = `import json,sys,os,stat,subprocess,hashlib
from pathlib import Path
expected=json.loads(sys.argv[1]);root=Path('/var/lib/ultra-ansible');auth=root/('recovery-controller-'+expected['request_sha256']+'.json')
def read(p):
 s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and not s.st_mode&0o022
 return p.read_bytes()
assert json.loads(read(auth))==expected
unit=Path('/etc/systemd/system/ultra-ansible-controller.service')
assert hashlib.sha256(read(unit)).hexdigest()==expected['candidate']['unit_sha256']
properties=subprocess.run(['systemctl','show','--property=ActiveState,MainPID,ControlGroup','ultra-ansible-controller.service'],check=True,capture_output=True,text=True,timeout=5)
values=dict(line.split('=',1) for line in properties.stdout.splitlines())
assert values['ActiveState']=='active' and values['ControlGroup']=='/system.slice/ultra-ansible-controller.service'
pid=Path('/proc')/values['MainPID'];assert os.readlink(pid/'exe')==expected['candidate']['directory']+'/ultra-install'
assert hashlib.sha256((pid/'exe').read_bytes()).hexdigest()==expected['candidate']['installer_sha256']
path=unit.parent/'ultra-ansible-controller.service.d/90-retained-primary.conf'
if os.path.lexists(path):
 assert read(path)==('[Unit]\nRefuseManualStart=no\nConditionPathExists='+str(auth)+'\n').encode()
 path.unlink();fd=os.open(path.parent,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
subprocess.run(['systemctl','daemon-reload'],check=True,timeout=20)
for name in ['ultra-recovery-reconcile.service','ultra-recovery-reconcile.timer']:
 assert read(unit.parent/(name+'.d/90-retained-primary.conf'))==b'[Unit]\nRefuseManualStart=yes\nConditionPathExists=/var/lib/ultra-ansible/retained-primary-admission-open\n'
`

// Pure observation: no Ansible job, admission publication, broker startup, lease
// transition or metadata overwrite. External deploy-operation reconcile uses it.
func observeRecoveryBrokerProof(ctx context.Context, r recoveryPreparationRequest, plan recoveryBrokerPlan, requireCandidate bool) error {
	proof, _ := plan.spec["proof"].(map[string]any)
	candidate, _ := proof["candidate"].(map[string]any)
	payload, _ := json.Marshal(
		map[string]any{
			"proof":                   proof,
			"candidate":               candidate,
			"operation_id":            lifecycleID(plan.directory),
			"scope_sha256":            plan.spec["scope_sha256"],
			"manifest_sha256":         r.ToolsManifestSHA256,
			"recovery_request_sha256": r.digest(),
			"require_candidate":       requireCandidate,
		},
	)
	source, err := ansibleassets.Bundle.ReadFile("library/ultra_controller_enforcement.py")
	if err != nil {
		return err
	}
	program := "__name__='recovery_proof_observer'\n" + string(
		source,
	) + "\np= json.loads(sys.argv[1]);print(json.dumps(observe_recovery_proof(p)))\n"
	// The embedded module imports no sys in its normal Ansible entrypoint.
	program = "import sys\n" + program
	output, err := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-c", program, string(payload)).Output()
	var observed struct {
		Verified  bool                    `json:"verified"`
		Lifecycle recoveryBrokerLifecycle `json:"lifecycle"`
	}
	if err != nil || len(output) > 16384 || decodeRetainedReconcile(output, &observed) != nil || !observed.Verified {
		return errors.New("recovery_broker_observation_unverified")
	}
	return nil
}

type recoveryBrokerInstance struct {
	PID          string `json:"pid"`
	StartTime    string `json:"start_time"`
	InstallerSHA string `json:"installer_sha256"`
	UnitSHA      string `json:"unit_sha256"`
}

func observeRecoveryBrokerInstance(ctx context.Context, plan recoveryBrokerPlan) (recoveryBrokerInstance, error) {
	var result recoveryBrokerInstance
	candidate := plan.spec["proof"].(map[string]any)["candidate"]
	raw, _ := json.Marshal(candidate)
	output, err := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-c", recoveryBrokerInstanceProgram, string(raw)).Output()
	if err != nil || len(output) > 4096 || decodeRetainedReconcile(output, &result) != nil || result.PID == "" || result.StartTime == "" {
		return result, errors.New("recovery_broker_instance_unverified")
	}
	return result, nil
}

const recoveryBrokerInstanceProgram = `import json,sys,os,subprocess,hashlib,stat
from pathlib import Path
expected=json.loads(sys.argv[1]);unit=Path('/etc/systemd/system/ultra-ansible-controller.service')
s=unit.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and not s.st_mode&0o022
unitsha=hashlib.sha256(unit.read_bytes()).hexdigest();assert unitsha==expected['unit_sha256']
r=subprocess.run(['systemctl','show','--property=ActiveState,MainPID,ControlPID,FragmentPath,ControlGroup','ultra-ansible-controller.service'],check=True,capture_output=True,text=True,timeout=5)
p=dict(line.split('=',1) for line in r.stdout.splitlines())
assert p['ActiveState']=='active' and p['ControlPID']=='0' and p['MainPID'].isdigit() and int(p['MainPID'])>1
assert p['FragmentPath']==str(unit) and p['ControlGroup']=='/system.slice/ultra-ansible-controller.service'
proc=Path('/proc')/p['MainPID'];assert (proc/'cgroup').read_bytes()==b'0::/system.slice/ultra-ansible-controller.service\n'
assert os.readlink(proc/'exe')==expected['directory']+'/ultra-install'
sha=hashlib.sha256((proc/'exe').read_bytes()).hexdigest();assert sha==expected['installer_sha256']
assert (proc/'cmdline').read_bytes().rstrip(b'\0').split(b'\0')==[os.fsencode(expected['directory']+'/ultra-install'),b'ansible-controller',b'--executable',os.fsencode(expected['directory']+'/venv/bin/ansible-playbook')]
start=(proc/'stat').read_text().rsplit(')',1)[1].split()[19];assert start.isdigit()
print(json.dumps({'pid':p['MainPID'],'start_time':start,'installer_sha256':sha,'unit_sha256':unitsha}))
`

func requireRecoveryBrokerSupervisor(r recoveryPreparationRequest) error {
	fail := errors.New("recovery_broker_authenticated_supervisor_required")
	raw, err := readRebuildInput(filepath.Join(deployOperationsRoot, "current.json"), true)
	var current struct {
		Schema  int    `json:"schema"`
		Request string `json:"request_sha256"`
	}
	if err != nil || decodeRetainedReconcile(raw, &current) != nil || current.Schema != 1 || !runtimeHostValidDigest(current.Request) {
		return fail
	}
	directory := filepath.Join(deployOperationsRoot, current.Request)
	raw, err = readRebuildInput(filepath.Join(directory, "request.json"), true)
	var envelope deployOperationRequest
	if err != nil || digestSHA256(raw) != current.Request || decodeRetainedReconcile(raw, &envelope) != nil || envelope.Schema != 2 ||
		envelope.Preparation == nil ||
		envelope.Preparation.digest() != r.digest() {
		return fail
	}
	state, err := readDeployOperation(directory, envelope)
	if err != nil || state.State != "running" {
		return fail
	}
	cgroup, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return fail
	}
	for _, line := range strings.Split(string(cgroup), "\n") {
		if strings.HasSuffix(line, ":/system.slice/ultra-deploy-"+current.Request+".service") {
			return nil
		}
	}
	return fail
}

// This validator never dispatches work, starts a broker, changes a gate, or
// acknowledges a descriptor. It tells the supervisor whether a separate
// authenticated metadata-resume action is possible after normal completion.
func verifyRecoveryBrokerHandoffMetadata(ctx context.Context, r recoveryPreparationRequest, args []string) error {
	if _, err := validateRecoveryPreparationRequest(r); err != nil {
		return err
	}
	if err := verifyRecoveryPreparationLegacyClosure(r); err != nil {
		return err
	}
	plan, err := recoveryUpgradePlanWithMode(r, args, false)
	if err != nil {
		return err
	}
	descriptor, err := readRecoveryBrokerPreflight(r, plan)
	if err != nil {
		return err
	}
	if err = verifyRecoveryBrokerJob(r, filepath.Join(r.StateDirectory, "ansible-broker-handoff")); err != nil {
		return err
	}
	lifecycle, err := readRecoveryBrokerLifecycle(plan.lock)
	if err != nil || lifecycle.ID != descriptor.OperationID || (lifecycle.Phase != "applying" && lifecycle.Phase != "checking") {
		return errors.New("recovery_broker_lifecycle_changed")
	}
	return observeRecoveryBrokerProof(ctx, r, plan, true)
}

// The only crash-resume path after the Ansible handoff completed. It performs
// descriptor acknowledgement and exact drop-in retirement, never a RunLocal
// mutation or reinstallation/restart. Only the exact running supervisor may call.
func resumeRecoveryBrokerHandoffMetadata(ctx context.Context, r recoveryPreparationRequest, args []string) error {
	if err := requireRecoveryBrokerSupervisor(r); err != nil {
		return err
	}
	if err := verifyRecoveryBrokerHandoffMetadata(ctx, r, args); err != nil {
		return err
	}
	in, err := validateRecoveryPreparationRequest(r)
	if err != nil {
		return err
	}
	plan, err := recoveryUpgradePlanWithMode(r, args, false)
	if err != nil {
		return err
	}
	descriptor, err := readRecoveryBrokerPreflight(r, plan)
	if err != nil {
		return err
	}
	if fence, e := deployansible.InspectExecutionFence(); e != nil {
		return e
	} else if fence != nil {
		if fence.JobDirectory != filepath.Join(r.StateDirectory, "ansible-broker-handoff") {
			return deployansible.ErrExecutionFenced
		}
		if e = deployansible.ReconcileExecutionFence(*fence); e != nil {
			return e
		}
	}
	operator, releaseOperator, err := withBootstrapOperatorLock(ctx, filepath.Dir(plan.directory))
	if err != nil {
		return err
	}
	defer releaseOperator()
	client := deployansible.Client{Socket: lifecycleSocket()}
	locked, release, err := client.WithLifecycleOperationLock(operator, plan.lock, descriptor.OperationID)
	if err != nil {
		return err
	}
	defer release()
	return finishRecoveryBrokerMetadata(ctx, locked, r, in, plan, descriptor, client)
}
