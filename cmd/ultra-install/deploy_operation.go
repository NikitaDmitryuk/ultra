package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const deployOperationsRoot = "/var/lib/ultra-ansible/deploy-operations"

// The immutable request contains paths and public candidate identities only.
// Runtime credentials stay in the installed runtime, never argv or this record.
type deployOperationRequest struct {
	Schema      int                         `json:"schema"`
	Args        []string                    `json:"args"`
	Preparation *recoveryPreparationRequest `json:"preparation,omitempty"`
}

type deployOperationState struct {
	Schema  int    `json:"schema"`
	Request string `json:"request_sha256"`
	Stage   string `json:"stage"`
	State   string `json:"state"`
	Reason  string `json:"reason,omitempty"`
}

func deployOperationIdentity(request deployOperationRequest, executable string) (string, error) {
	if (request.Schema != 1 && request.Schema != 2) || (request.Schema == 2) != (request.Preparation != nil) ||
		len(request.Args) == 0 || request.Args[0] != "operator-upgrade" {
		return "", errors.New("deploy_operation_request_invalid")
	}
	// Do not permit arbitrary executable arguments through the supervisor.
	values := map[string]string{}
	booleans := map[string]bool{"--lifecycle": true, "--forward-only": true}
	allowed := map[string]bool{"--config": true, "--release-dir": true, "--source-commit": true,
		"--version": true, "--manifest-sha256": true, "--config-sha256": true,
		"--job-dir": true, "--secrets-source": true, "--subscription-probe-url-file": true,
		"--forward-journal-file": true, "--forward-journal-sha256": true,
		"--forward-prior-candidate": true, "--forward-prior-journal-file": true, "--forward-prior-journal-sha256": true}
	for i := 1; i < len(request.Args); i++ {
		key := request.Args[i]
		if _, exists := values[key]; exists {
			return "", errors.New("deploy_operation_argument_duplicate")
		}
		if booleans[key] {
			values[key] = "true"
			continue
		}
		if !allowed[key] || i+1 >= len(request.Args) {
			return "", errors.New("deploy_operation_argument_invalid")
		}
		i++
		values[key] = request.Args[i]
	}
	for _, key := range []string{"--config", "--release-dir", "--source-commit", "--version", "--manifest-sha256", "--config-sha256"} {
		if values[key] == "" {
			return "", errors.New("deploy_operation_candidate_required")
		}
	}
	for _, key := range []string{"--config", "--release-dir", "--job-dir", "--subscription-probe-url-file", "--forward-journal-file", "--forward-prior-candidate", "--forward-prior-journal-file"} {
		if path := values[key]; path != "" && (!filepath.IsAbs(path) || filepath.Clean(path) != path) {
			return "", errors.New("deploy_operation_absolute_paths_required")
		}
	}
	if source := values["--secrets-source"]; source != "" && source != "installed-runtime" {
		return "", errors.New("deploy_operation_installed_secrets_required")
	}
	raw, err := readRebuildInput(values["--config"], true)
	if err != nil || digestSHA256(raw) != values["--config-sha256"] {
		return "", errors.New("deploy_operation_config_changed")
	}
	if executable == "" {
		executable = filepath.Join(values["--release-dir"], "ultra-install-linux-"+runtime.GOARCH)
	}
	if _, err = verifyOperatorUpgradeRelease(values["--release-dir"], values["--source-commit"], values["--version"], values["--manifest-sha256"], executable); err != nil {
		return "", fmt.Errorf("deploy_operation_candidate_invalid: %w", err)
	}
	if request.Preparation != nil {
		p := *request.Preparation
		if p.UpgradeConfigPath != values["--config"] || p.UpgradeConfigSHA256 != values["--config-sha256"] ||
			p.ToolsReleaseDirectory != values["--release-dir"] || p.ToolsManifestSHA256 != values["--manifest-sha256"] || values["--forward-only"] != "" {
			return "", errors.New("deploy_operation_preparation_candidate_changed")
		}
		if _, err = validateRecoveryPreparationRequest(p); err != nil {
			return "", err
		}
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	return digestSHA256(encoded), nil
}

func saveDeployOperation(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if _, err = os.Lstat(path); err == nil {
		if err = operatorPrivate(path, false); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".publish-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

func readDeployOperation(directory string, request deployOperationRequest) (deployOperationState, error) {
	var state deployOperationState
	raw, err := readRebuildInput(filepath.Join(directory, "request.json"), true)
	var saved deployOperationRequest
	if err != nil || decodeRetainedReconcile(raw, &saved) != nil || !reflect.DeepEqual(saved, request) {
		return state, errors.New("deploy_operation_request_changed")
	}
	raw, err = readRebuildInput(filepath.Join(directory, "state.json"), true)
	if err != nil || decodeRetainedReconcile(raw, &state) != nil || state.Schema != 1 {
		return state, errors.New("deploy_operation_state_invalid")
	}
	identity, _ := json.Marshal(request)
	if state.Request != digestSHA256(identity) {
		return state, errors.New("deploy_operation_binding_changed")
	}
	valid := deployOperationStageValid(request, state.Stage)
	switch state.State {
	case "prepared", "submitted", "running":
		valid = valid && state.Reason == ""
	case "retry_prepared":
		valid = valid && state.Stage != "status" && state.Reason == ""
	case "blocked":
		_, known := deployOperationNextActions[state.Reason]
		valid = valid && (known || state.Reason == "deploy_operation_"+state.Stage+"_failed")
	case "completed":
		valid = state.Stage == "status" && state.Reason == ""
	default:
		valid = false
	}
	if !valid {
		return state, errors.New("deploy_operation_state_invalid")
	}
	return state, nil
}

var deployPreparationPhases = []string{
	"origins_sealed",
	"legacy_closed",
	"enforcement_preflight",
	"tools_staged",
	"monitor_initialized",
	"recovery_reconciled",
	"readiness_verified",
	"broker_handoff",
}

func deployOperationStageValid(request deployOperationRequest, stage string) bool {
	if stage == "upgrade" || stage == "status" {
		return true
	}
	if request.Preparation != nil {
		for _, phase := range deployPreparationPhases {
			if phase == stage {
				return true
			}
		}
	}
	return false
}

func initialDeployOperationStage(request deployOperationRequest) string {
	if request.Preparation != nil {
		return deployPreparationPhases[0]
	}
	return "upgrade"
}

func deployOperationLock(directory string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(directory, "execution.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = operatorPrivate(f.Name(), false); err != nil {
		_ = f.Close()
		return nil, err
	}
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		_ = f.Close()
		return nil, errors.New("deploy_operation_busy")
	}
	return f, nil
}

// A crash after upgrade completion must never move the operation back to upgrade.
func prepareDeploySubmission(directory string, request deployOperationRequest, restart bool) error {
	state, err := readDeployOperation(directory, request)
	if err != nil {
		return err
	}
	if state.State == "completed" || (!restart && state.State != "prepared") {
		return errors.New("deploy_operation_submission_invalid")
	}
	if restart && state.Stage != "status" && state.State != "blocked" {
		return errors.New("deploy_operation_execution_uncertain")
	}
	state.State, state.Reason = "submitted", ""
	if restart && state.Stage != "status" {
		state.State = "retry_prepared"
	}
	return saveDeployOperation(filepath.Join(directory, "state.json"), state)
}

// runDeployOperation is called only by the independently supervised unit.
// A running upgrade is never replayed: a crash requires reconciliation.
func runDeployOperation(ctx context.Context, directory string, request deployOperationRequest,
	run func(context.Context, []string) error) error {
	return runDeployOperationWithFinalObservation(ctx, directory, request, run, runDeployPostActivationReconcile)
}

func runDeployOperationWithFinalObservation(ctx context.Context, directory string, request deployOperationRequest,
	run func(context.Context, []string) error, reconcile func(context.Context, []string) error) error {
	observeFinal := func(ctx context.Context, args []string) error {
		if len(args) != 0 && args[0] == "status" {
			if err := reconcile(ctx, request.Args); err != nil {
				return err
			}
		}
		return run(ctx, args)
	}
	return runDeployOperationPhases(ctx, directory, request, observeFinal, runDeployPreparationPhase, verifyDeployPreparationPhase)
}

// Preparation executes in this process: an extra supervisor would break the
// authenticated origin census and split ownership of the deployment operation.
func runDeployOperationPhases(ctx context.Context, directory string, request deployOperationRequest,
	run func(context.Context, []string) error,
	prepare func(context.Context, string, recoveryPreparationRequest, []string) error,
	observe func(context.Context, string, recoveryPreparationRequest, []string) error) error {
	return runDeployOperationSteps(ctx, directory, request, run, prepare, observe, resumeDeployPreparationMetadata)
}

func runDeployOperationSteps(ctx context.Context, directory string, request deployOperationRequest,
	run func(context.Context, []string) error,
	prepare func(context.Context, string, recoveryPreparationRequest, []string) error,
	observe func(context.Context, string, recoveryPreparationRequest, []string) error,
	resumeMetadata func(context.Context, string, recoveryPreparationRequest, []string) error) error {
	lock, err := deployOperationLock(directory)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	state, err := readDeployOperation(directory, request)
	if err != nil {
		return err
	}
	if state.State == "completed" {
		return nil
	}
	if state.Stage == "upgrade" && state.State != "prepared" && state.State != "submitted" && state.State != "retry_prepared" {
		return errors.New("deploy_operation_execution_uncertain")
	}
	if !deployOperationStageValid(request, state.Stage) {
		return errors.New("deploy_operation_stage_invalid")
	}
	save := func() error { return saveDeployOperation(filepath.Join(directory, "state.json"), state) }
	for state.Stage != "upgrade" && state.Stage != "status" {
		phase := state.Stage
		args := append([]string(nil), request.Args...)
		switch state.State {
		case "running", "blocked":
			// A lost coordinator may have completed its child before persisting
			// the next phase. Observe exact terminal evidence, never redispatch.
			if err = observe(ctx, phase, *request.Preparation, request.Args); err != nil {
				if phase != "broker_handoff" || state.State != "running" ||
					resumeMetadata(ctx, phase, *request.Preparation, request.Args) != nil {
					return errors.New("deploy_operation_execution_uncertain")
				}
				if err = observe(ctx, phase, *request.Preparation, request.Args); err != nil {
					return errors.New("deploy_operation_execution_uncertain")
				}
			}
		case "prepared", "submitted", "retry_prepared":
			metadataOnly := phase == "broker_handoff" && state.State == "retry_prepared"
			if state.State == "retry_prepared" {
				args = append(args, "--retry-failed")
			}
			state.State, state.Reason = "running", ""
			if err = save(); err != nil {
				return err
			}
			if metadataOnly {
				err = resumeMetadata(ctx, phase, *request.Preparation, request.Args)
			} else {
				err = prepare(ctx, phase, *request.Preparation, args)
			}
			if err != nil {
				state.State, state.Reason = "blocked", deployOperationFailureReason(phase, err)
				if saveErr := save(); saveErr != nil {
					return saveErr
				}
				return errors.New(state.Reason)
			}
		default:
			return errors.New("deploy_operation_execution_uncertain")
		}
		state.Stage, state.State, state.Reason = nextDeployOperationStage(phase), "prepared", ""
		if err = save(); err != nil {
			return err
		}
	}
	if state.Stage == "upgrade" {
		retry := state.State == "retry_prepared"
		state.State = "running"
		if err = save(); err != nil {
			return err
		}
		args := append([]string(nil), request.Args...)
		if retry {
			args = append(args, "--retry-failed")
		}
		if err = run(ctx, args); err != nil {
			state.State, state.Reason = "blocked", deployOperationFailureReason("upgrade", err)
			if saveErr := save(); saveErr != nil {
				return saveErr
			}
			return errors.New(state.Reason)
		}
		state.Stage, state.State, state.Reason = "status", "prepared", ""
		if err = save(); err != nil {
			return err
		}
	}
	// Final observation is independently retryable; it cannot repeat upgrade.
	config := ""
	for i, arg := range request.Args {
		if arg == "--config" && i+1 < len(request.Args) {
			config = request.Args[i+1]
		}
	}
	state.State, state.Reason = "running", ""
	if err = save(); err != nil {
		return err
	}
	if err = run(ctx, []string{"status", "--lifecycle", "--config", config}); err != nil {
		state.State, state.Reason = "blocked", deployOperationFailureReason("status", err)
		if saveErr := save(); saveErr != nil {
			return saveErr
		}
		return errors.New(state.Reason)
	}
	state.State, state.Reason = "completed", ""
	return save()
}

func nextDeployOperationStage(stage string) string {
	for i, phase := range deployPreparationPhases {
		if phase == stage {
			if i+1 < len(deployPreparationPhases) {
				return deployPreparationPhases[i+1]
			}
			return "upgrade"
		}
	}
	return ""
}

func runDeployPreparationPhase(ctx context.Context, phase string, r recoveryPreparationRequest, args []string) error {
	switch phase {
	case "legacy_closed":
		return closeRecoveryPreparationLegacy(ctx, r)
	case "enforcement_preflight":
		return runRecoveryBrokerPreflight(ctx, r, args)
	case "broker_handoff":
		return runRecoveryBrokerHandoff(ctx, r, args)
	}
	return runRecoveryPreparationPhase(ctx, phase, r, args)
}

func verifyDeployPreparationPhase(ctx context.Context, phase string, r recoveryPreparationRequest, args []string) error {
	switch phase {
	case "legacy_closed":
		return verifyRecoveryPreparationLegacyClosure(r)
	case "enforcement_preflight":
		return verifyRecoveryBrokerPreflight(ctx, r, args)
	case "broker_handoff":
		return verifyRecoveryBrokerHandoff(ctx, r, args)
	}
	return verifyRecoveryPreparationPhase(ctx, phase, r)
}

func resumeDeployPreparationMetadata(ctx context.Context, phase string, r recoveryPreparationRequest, args []string) error {
	if phase != "broker_handoff" {
		return errors.New("deploy_operation_metadata_resume_invalid")
	}
	if err := verifyRecoveryBrokerHandoffMetadata(ctx, r, args); err != nil {
		return err
	}
	return resumeRecoveryBrokerHandoffMetadata(ctx, r, args)
}

func deployUnitName(identity string) string { return "ultra-deploy-" + identity + ".service" }

func deployUnitArgs(identity, executable, directory string) []string {
	return []string{"--unit=" + deployUnitName(identity), "--no-block", "--property=Type=oneshot",
		"--property=RemainAfterExit=yes", "--property=KillMode=control-group", "--property=UMask=0077",
		"--property=TimeoutStartSec=infinity", "--property=TimeoutStopSec=30", "--property=Restart=no",
		"--property=StandardOutput=append:" + filepath.Join(directory, "execution.log"), "--property=StandardError=inherit",
		executable, "deploy-operation", "run", "--directory", directory}
}

func deploySubprocess(ctx context.Context, executable string, args []string) error {
	command := exec.CommandContext(ctx, executable, args...)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	return command.Run()
}

func waitDeployOperation(ctx context.Context, directory string, request deployOperationRequest, out io.Writer) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	last := ""
	for {
		state, err := readDeployOperation(directory, request)
		if err != nil {
			return err
		}
		current := state.Stage + ":" + state.State
		if current != last {
			if _, err = fmt.Fprintln(out, "deploy-operation:", current); err != nil {
				return err
			}
			last = current
		}
		if state.State == "completed" {
			return nil
		}
		if state.State == "blocked" {
			return errors.New(state.Reason)
		}
		probe, stop := context.WithTimeout(ctx, 3*time.Second)
		active, probeErr := exec.CommandContext(probe, "systemctl", "show", deployUnitName(state.Request), "--property=ActiveState", "--value").
			Output()
		stop()
		if probeErr != nil || (strings.TrimSpace(string(active)) != "active" && strings.TrimSpace(string(active)) != "activating") {
			return errors.New("deploy_operation_executor_unavailable_reconciliation_required")
		}
		select {
		case <-ctx.Done():
			return errors.New("deploy_operation_client_disconnected_executor_retained")
		case <-ticker.C:
		}
	}
}

func admitDeployOperation(root, identity string) error {
	path := filepath.Join(root, "current.json")
	var active struct {
		Schema  int    `json:"schema"`
		Request string `json:"request_sha256"`
	}
	_, err := os.Lstat(path)
	if err == nil {
		raw, readErr := readRebuildInput(path, true)
		if readErr != nil {
			return readErr
		}
		if decodeRetainedReconcile(raw, &active) != nil || active.Schema != 1 || len(active.Request) != 64 ||
			strings.Trim(active.Request, "0123456789abcdef") != "" {
			return errors.New("deploy_operation_admission_invalid")
		}
		if active.Request == identity {
			return nil
		}
		previous := filepath.Join(root, active.Request)
		requestRaw, readErr := readRebuildInput(filepath.Join(previous, "request.json"), true)
		var request deployOperationRequest
		if readErr != nil || decodeRetainedReconcile(requestRaw, &request) != nil {
			return errors.New("deploy_operation_conflict")
		}
		state, stateErr := readDeployOperation(previous, request)
		if stateErr != nil || state.State != "completed" {
			return errors.New("deploy_operation_conflict")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	active.Schema, active.Request = 1, identity
	return saveDeployOperation(path, active)
}

func cleanDeployRetry(args []string) ([]string, bool) {
	clean := make([]string, 0, len(args))
	retry := false
	for _, arg := range args {
		if arg == "--retry-failed" {
			retry = true
		} else {
			clean = append(clean, arg)
		}
	}
	return clean, retry
}

func checkedDeployDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) != deployOperationsRoot ||
		len(filepath.Base(path)) != 64 || strings.Trim(filepath.Base(path), "0123456789abcdef") != "" {
		return errors.New("deploy_operation_directory_invalid")
	}
	return operatorPrivate(path, true)
}
