package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

func runDeployOperationCommand(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("deploy_operation_action_required")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if args[0] == "background-ready" {
		if len(args) != 1 {
			return errors.New("deploy_operation_arguments_invalid")
		}
		return deployansible.DeploymentBackgroundReady()
	}
	if args[0] == "export-preparation" {
		return runExportRecoveryInputs(ctx, args[1:], out)
	}
	if args[0] == "import-preparation" {
		return runImportRecoveryInputs(ctx, args[1:], out)
	}
	if args[0] == "start" {
		if os.Geteuid() != 0 {
			return errors.New("deploy_operation_start_arguments_invalid")
		}
		fs := flag.NewFlagSet("deploy-operation start", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		preparationFile := fs.String("preparation-file", "", "immutable recovery preparation request")
		preparationSHA := fs.String("preparation-sha256", "", "preparation file digest")
		if fs.Parse(args[1:]) != nil || fs.NArg() == 0 {
			return errors.New("deploy_operation_start_arguments_invalid")
		}
		clean, retry := cleanDeployRetry(fs.Args())
		request := deployOperationRequest{Schema: 1, Args: clean}
		if *preparationFile != "" || *preparationSHA != "" {
			if !filepath.IsAbs(*preparationFile) || !runtimeHostValidDigest(*preparationSHA) {
				return errors.New("deploy_operation_preparation_arguments_invalid")
			}
			raw, err := readRebuildInput(*preparationFile, true)
			var preparation recoveryPreparationRequest
			if err != nil || digestSHA256(raw) != *preparationSHA || decodeRetainedReconcile(raw, &preparation) != nil {
				return errors.New("deploy_operation_preparation_changed")
			}
			preparation, err = bindRecoveryPreparationRequest(ctx, preparation)
			if err != nil {
				return err
			}
			request.Schema, request.Preparation = 2, &preparation
		}
		return startDeployOperation(ctx, request, retry, out)
	}
	if args[0] != "run" && args[0] != "inspect" && args[0] != "reconcile" {
		return errors.New("deploy_operation_action_invalid")
	}
	fs := flag.NewFlagSet("deploy-operation", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	directory := fs.String("directory", "", "immutable deployment operation directory")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 {
		return errors.New("deploy_operation_arguments_invalid")
	}
	if *directory == "" && (args[0] == "inspect" || args[0] == "reconcile") {
		fence, err := deployansible.InspectExecutionFence()
		if err != nil {
			return err
		}
		if args[0] == "reconcile" && fence != nil {
			if err = deployansible.ReconcileExecutionFence(*fence); err != nil {
				return err
			}
			fence, err = deployansible.InspectExecutionFence()
			if err != nil {
				return err
			}
		}
		deployment, inspectErr := inspectCurrentDeployOperation()
		if inspectErr != nil {
			return inspectErr
		}
		return json.NewEncoder(out).Encode(map[string]any{"execution": fence, "deployment": deployment})
	}
	if err := checkedDeployDirectory(*directory); err != nil {
		return err
	}
	raw, err := readRebuildInput(filepath.Join(*directory, "request.json"), true)
	var request deployOperationRequest
	if err != nil || decodeRetainedReconcile(raw, &request) != nil {
		return errors.New("deploy_operation_request_invalid")
	}
	executableIdentity := ""
	if args[0] == "run" {
		executableIdentity = "/proc/self/exe"
	}
	identity, err := deployOperationIdentity(request, executableIdentity)
	if err != nil || filepath.Base(*directory) != identity {
		return errors.New("deploy_operation_identity_changed")
	}
	state, err := readDeployOperation(*directory, request)
	if err != nil {
		return err
	}
	if args[0] == "inspect" {
		return json.NewEncoder(out).Encode(observeDeployOperation(state))
	}
	if args[0] == "reconcile" {
		// Exact normal completion is the only supported automatic proof.
		// Unknown legacy remote descendants cannot be cleared by this command.
		if state.Stage == "upgrade" && state.State == "blocked" {
			if err = reconcileDeployExecution(request); err != nil {
				return err
			}
		} else if state.State != "completed" && state.Stage != "status" {
			lock, lockErr := deployOperationLock(*directory)
			if lockErr != nil {
				return lockErr
			}
			defer func() { _ = lock.Close() }()
			state, err = reconcileDeployPreparationCheckpoint(ctx, *directory, request, verifyDeployPreparationPhase)
			if err != nil {
				return err
			}
		}
		return json.NewEncoder(out).Encode(observeDeployOperation(state))
	}
	if os.Geteuid() != 0 || verifyDeployUnit(identity) != nil {
		return errors.New("deploy_operation_supervisor_required")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	return runDeployOperation(ctx, *directory, request, func(ctx context.Context, args []string) error {
		return deploySubprocess(ctx, executable, args)
	})
}

func inspectCurrentDeployOperation() (*deployOperationObservation, error) {
	path := filepath.Join(deployOperationsRoot, "current.json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	raw, err := readRebuildInput(path, true)
	var active struct {
		Schema  int    `json:"schema"`
		Request string `json:"request_sha256"`
	}
	if err != nil || decodeRetainedReconcile(raw, &active) != nil || active.Schema != 1 {
		return nil, errors.New("deploy_operation_admission_invalid")
	}
	directory := filepath.Join(deployOperationsRoot, active.Request)
	if err = checkedDeployDirectory(directory); err != nil {
		return nil, err
	}
	raw, err = readRebuildInput(filepath.Join(directory, "request.json"), true)
	var request deployOperationRequest
	if err != nil || decodeRetainedReconcile(raw, &request) != nil {
		return nil, errors.New("deploy_operation_request_invalid")
	}
	state, err := readDeployOperation(directory, request)
	if err != nil || state.Request != active.Request {
		return nil, errors.New("deploy_operation_binding_changed")
	}
	observation := observeDeployOperation(state)
	return &observation, nil
}

func verifyDeployUnit(identity string) error {
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasSuffix(line, ":/system.slice/"+deployUnitName(identity)) {
			return nil
		}
	}
	return errors.New("deploy_operation_supervisor_required")
}

func startDeployOperation(ctx context.Context, request deployOperationRequest, retry bool, out io.Writer) error {
	identity, err := deployOperationIdentity(request, "/proc/self/exe")
	if err != nil {
		return err
	}
	if err = ensurePrivateBootstrapDirectory(deployOperationsRoot); err != nil {
		return err
	}
	if err = syncUpgradeDirectory(filepath.Dir(deployOperationsRoot)); err != nil {
		return err
	}
	// Admission is shared across all candidate operation directories. The
	// executor has its own lock, so the submitting SSH client need not survive.
	admission, err := deployOperationLock(deployOperationsRoot)
	if err != nil {
		return err
	}
	defer func() { _ = admission.Close() }()
	if err = admitDeployOperation(deployOperationsRoot, identity); err != nil {
		return err
	}
	directory := filepath.Join(deployOperationsRoot, identity)
	if err = ensurePrivateBootstrapDirectory(directory); err != nil {
		return err
	}
	if err = checkedDeployDirectory(directory); err != nil {
		return err
	}
	stopObserving, err := publishDeployOperationObserver(directory, identity)
	if err != nil {
		return err
	}
	defer stopObserving()
	lock, err := deployOperationLock(directory)
	if err != nil {
		if err.Error() != "deploy_operation_busy" {
			return err
		}
		// The independent executor already owns this operation. Observe only.
		_ = admission.Close()
		return waitDeployOperation(ctx, directory, request, out)
	}
	launch, restart := false, false
	if _, err = os.Lstat(filepath.Join(directory, "request.json")); os.IsNotExist(err) {
		if err = saveDeployOperation(filepath.Join(directory, "request.json"), request); err == nil {
			err = saveDeployOperation(
				filepath.Join(directory, "state.json"),
				deployOperationState{1, identity, initialDeployOperationStage(request), "prepared", ""},
			)
		}
		launch = err == nil
	} else if err == nil {
		var state deployOperationState
		state, err = readDeployOperation(directory, request)
		if err == nil {
			switch {
			case state.State == "completed":
				_ = lock.Close()
				return nil
			case state.Stage == "status" && retry:
				// Restart the same unit; run preserves the status-only stage.
				launch, restart = true, true
			case state.Stage == "upgrade" && state.State == "blocked" && retry:
				err = reconcileDeployExecution(request)
				launch, restart = err == nil, err == nil
			case request.Preparation != nil && state.Stage == "broker_handoff" && (state.State == "running" || state.State == "blocked" || state.State == "retry_prepared"):
				if _, err = reconcileDeployPreparationCheckpoint(ctx, directory, request, verifyDeployPreparationPhase); err == nil {
					launch = true
				} else if err = verifyRecoveryBrokerHandoffMetadata(ctx, *request.Preparation, request.Args); err == nil {
					// Only descriptor acknowledgement and drop-in metadata remain;
					// retry_prepared on this phase can never run the Ansible job.
					state.State, state.Reason = "blocked", "deploy_operation_broker_handoff_failed"
					err = saveDeployOperation(filepath.Join(directory, "state.json"), state)
					launch, restart = err == nil, err == nil
				}
			case request.Preparation != nil && state.Stage != "upgrade" && state.Stage != "status" && retry && state.State == "blocked":
				// The phase handler still requires the exact normal Ansible
				// completion before RunLocalRetryFailed may create a generation.
				launch, restart = true, true
			case request.Preparation != nil && state.Stage != "upgrade" && state.Stage != "status" && (state.State == "running" || state.State == "blocked"):
				_, err = reconcileDeployPreparationCheckpoint(ctx, directory, request, verifyDeployPreparationPhase)
				launch = err == nil
			case state.State == "blocked":
				err = errors.New(state.Reason)
			case state.State == "prepared":
				launch = true
			}
		}
	}
	if err == nil && launch {
		err = prepareDeploySubmission(directory, request, restart)
		if err == nil {
			// Persist the operation directory entry before handing off dispatch.
			err = syncUpgradeDirectory(deployOperationsRoot)
		}
	}
	_ = lock.Close()
	if err != nil {
		return err
	}
	if launch {
		executable, executableErr := os.Executable()
		if executableErr != nil {
			return executableErr
		}
		err = launchDeployUnit(ctx, identity, executable, directory)
		if err != nil {
			return errors.New("deploy_operation_submission_uncertain")
		}
	}
	_ = admission.Close()
	if _, err = fmt.Fprintln(out, "deploy-operation:", identity); err != nil {
		return err
	}
	return waitDeployOperation(ctx, directory, request, out)
}

func reconcileDeployExecution(request deployOperationRequest) error {
	fence, err := deployansible.InspectExecutionFence()
	if err != nil || fence == nil {
		return err
	}
	job := ""
	version := ""
	for i := 1; i+1 < len(request.Args); i++ {
		switch request.Args[i] {
		case "--job-dir":
			job = request.Args[i+1]
		case "--version":
			version = request.Args[i+1]
		}
	}
	if job == "" {
		job = filepath.Join("/var/lib/ultra-ansible", "upgrade-"+version)
	}
	rel, err := filepath.Rel(job, fence.JobDirectory)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return errors.New("deploy_operation_execution_conflict")
	}
	return deployansible.ReconcileExecutionFence(*fence)
}

// Transient units disappear on reboot. Only a legitimately prepared checkpoint
// reaches this function; an unknown dispatch is never recreated here.
func launchDeployUnit(ctx context.Context, identity, executable, directory string) error {
	raw, err := exec.CommandContext(ctx, "systemctl", "show", deployUnitName(identity), "--property=LoadState", "--value").Output()
	if err != nil {
		return err
	}
	switch strings.TrimSpace(string(raw)) {
	case "not-found":
		return exec.CommandContext(ctx, "systemd-run", deployUnitArgs(identity, executable, directory)...).Run()
	case "loaded":
		if err = exec.CommandContext(ctx, "systemctl", "reset-failed", deployUnitName(identity)).Run(); err != nil {
			return err
		}
		return exec.CommandContext(ctx, "systemctl", "start", "--no-block", deployUnitName(identity)).Run()
	default:
		return errors.New("deploy_operation_unit_unavailable")
	}
}

// Caller owns the operation lock. This is observation and a durable checkpoint
// only; the next phase requires a separate supervised execution.
func reconcileDeployPreparationCheckpoint(ctx context.Context, directory string, request deployOperationRequest,
	observe func(context.Context, string, recoveryPreparationRequest, []string) error) (deployOperationState, error) {
	state, err := readDeployOperation(directory, request)
	if err != nil {
		return state, err
	}
	if request.Preparation == nil || state.Stage == "upgrade" || state.Stage == "status" ||
		(state.State != "running" && state.State != "blocked") {
		return state, errors.New("deploy_operation_execution_uncertain")
	}
	if err = observe(ctx, state.Stage, *request.Preparation, request.Args); err != nil {
		return state, errors.New("deploy_operation_execution_uncertain")
	}
	state.Stage, state.State, state.Reason = nextDeployOperationStage(state.Stage), "prepared", ""
	return state, saveDeployOperation(filepath.Join(directory, "state.json"), state)
}
