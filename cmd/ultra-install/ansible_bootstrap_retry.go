package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

const bootstrapBrokerLockDirectory = "/var/lib/ultra-ansible"
const bootstrapBrokerSocket = "/run/ultra-ansible/controller.sock"

type frozenBootstrapRetryDependencies struct {
	readPrivate     func(string) ([]byte, error)
	readRootPrivate func(string) ([]byte, error)
	machine         func(*installplan.InstallPlan) bool
	nativeMachine   func(string) bool
	operator        func(context.Context, string) (context.Context, func(), error)
	attach          func(context.Context, string, string) (context.Context, func(), error)
	replay          func(context.Context, string, string, string) (deployansible.Receipt, error)
	remoteLock      func(context.Context, string) (context.Context, func(), error)
}

func frozenBootstrapStageLeaseDependencies() frozenBootstrapRetryDependencies {
	return frozenBootstrapRetryDependencies{
		readPrivate: readBootstrapGenerationInput, readRootPrivate: readRootPrivateBootstrapRetry, machine: localLifecycleMachineIdentity, nativeMachine: validNativeRetryMachine,
		operator: func(ctx context.Context, path string) (context.Context, func(), error) {
			if err := validateBootstrapRetryOperatorDirectory(path); err != nil {
				return ctx, nil, err
			}
			return deployansible.WithOperationLock(ctx, path)
		},
		attach: func(ctx context.Context, lock, id string) (context.Context, func(), error) {
			return (deployansible.Client{Socket: bootstrapBrokerSocket}).WithActiveLifecycleOperationLock(ctx, lock, id)
		},
		remoteLock: deployansible.WithOperationLock,
	}
}

// This adapter is internal to fixed root CLI protocols, never a service API.
func withFrozenBootstrapStageLease(
	ctx context.Context,
	directory string,
	action func(context.Context) (deployansible.Receipt, error),
) (deployansible.Receipt, error) {
	return withFrozenBootstrapStageLeaseWith(ctx, directory, frozenBootstrapStageLeaseDependencies(), action)
}

func retryFrozenBootstrapOperator(ctx context.Context, directory, python, executable string) (deployansible.Receipt, error) {
	return withFrozenBootstrapStageLease(ctx, directory, func(locked context.Context) (deployansible.Receipt, error) {
		return deployansible.RetryFrozenBootstrap(locked, directory, python, executable)
	})
}

func readRootPrivateBootstrapRetry(path string) ([]byte, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("root_private_bootstrap_retry_required")
	}
	for _, candidate := range []string{filepath.Dir(path), path} {
		info, err := os.Lstat(candidate)
		if err != nil {
			return nil, err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || info.Mode().Perm()&0077 != 0 || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("root_private_bootstrap_retry_required")
		}
	}
	return readBootstrapGenerationInput(path)
}

func retryFrozenBootstrapOperatorWith(
	ctx context.Context,
	directory, python, executable string,
	deps frozenBootstrapRetryDependencies,
) (deployansible.Receipt, error) {
	return withFrozenBootstrapStageLeaseWith(ctx, directory, deps, func(locked context.Context) (deployansible.Receipt, error) {
		return deps.replay(locked, directory, python, executable)
	})
}

func withFrozenBootstrapStageLeaseWith(
	ctx context.Context,
	directory string,
	deps frozenBootstrapRetryDependencies,
	action func(context.Context) (deployansible.Receipt, error),
) (deployansible.Receipt, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return deployansible.Receipt{}, errors.New("retry_stage_directory_invalid")
	}
	attempt := filepath.Dir(directory)
	requestRaw, err := deps.readPrivate(filepath.Join(directory, "request.json"))
	if err != nil {
		return deployansible.Receipt{}, err
	}
	jobRaw, err := deps.readPrivate(filepath.Join(directory, "job.json"))
	if err != nil {
		return deployansible.Receipt{}, err
	}
	var request struct {
		Inventory map[string]any `json:"inventory"`
		Variables map[string]any `json:"variables"`
	}
	var job struct {
		Operation string `json:"operation"`
		Schema    int    `json:"schema_version"`
		Hash      string `json:"request_sha256"`
		Binary    string `json:"binary_sha256"`
	}
	digest := sha256.Sum256(requestRaw)
	if json.Unmarshal(requestRaw, &request) != nil || json.Unmarshal(jobRaw, &job) != nil || job.Schema != 1 ||
		job.Hash != hex.EncodeToString(digest[:]) ||
		job.Binary != job.Hash {
		return deployansible.Receipt{}, errors.New("retry_inputs_invalid")
	}
	switch job.Operation {
	case "bootstrap",
		"bootstrap-postgres",
		"bootstrap-exit",
		"bootstrap-bridge",
		"ingress",
		"configure-bot",
		"bootstrap-automation",
		"reserve-rolledback-bootstrap":
	default:
		return deployansible.Receipt{}, errors.New("retry_bootstrap_operation_required")
	}
	lock, ok := request.Variables["ultra_lock_directory"].(string)
	if !ok || !filepath.IsAbs(lock) {
		return deployansible.Receipt{}, errors.New("retry_frozen_lock_directory_required")
	}
	validateLockedStage := func() error {
		for _, input := range []struct {
			path     string
			original []byte
		}{{filepath.Join(directory, "request.json"), requestRaw}, {filepath.Join(directory, "job.json"), jobRaw}} {
			raw, readErr := deps.readPrivate(input.path)
			if readErr != nil {
				return readErr
			}
			if !bytes.Equal(raw, input.original) {
				return errors.New("retry_frozen_inputs_changed")
			}
		}
		receiptRaw, receiptErr := deps.readPrivate(filepath.Join(directory, "receipt.json"))
		if receiptErr == nil {
			var receipt map[string]any
			if json.Unmarshal(receiptRaw, &receipt) != nil || receipt["schema_version"] != float64(job.Schema) ||
				receipt["operation"] != job.Operation ||
				receipt["request_sha256"] != job.Hash ||
				receipt["binary_sha256"] != job.Binary ||
				(receipt["state"] != "running" && receipt["state"] != "failed" && receipt["state"] != "succeeded") {
				return errors.New("retry_frozen_receipt_invalid")
			}
		} else if !os.IsNotExist(receiptErr) {
			return receiptErr
		}
		return nil
	}
	native := func(operatorDirectory string, modePath string, originalMode []byte) (deployansible.Receipt, error) {
		if filepath.Clean(lock) == bootstrapBrokerLockDirectory {
			return deployansible.Receipt{}, errors.New("retry_local_broker_attachment_required")
		}
		if !filepath.IsAbs(lock) || filepath.Clean(lock) != lock {
			return deployansible.Receipt{}, errors.New("retry_frozen_execution_invalid")
		}
		if operatorDirectory == "" {
			operatorDirectory = filepath.Join(lock, "operator")
		}
		if filepath.Clean(operatorDirectory) != operatorDirectory || filepath.Dir(operatorDirectory) != lock ||
			filepath.Base(operatorDirectory) != "operator" {
			return deployansible.Receipt{}, errors.New("retry_original_operator_lock_required_resume_full_apply")
		}
		operator, operatorRelease, err := deps.operator(ctx, operatorDirectory)
		if err != nil {
			return deployansible.Receipt{}, err
		}
		defer operatorRelease()
		if err = validateLockedStage(); err != nil {
			return deployansible.Receipt{}, err
		}
		rawMode, modeReadErr := deps.readPrivate(modePath)
		if modeReadErr != nil {
			return deployansible.Receipt{}, modeReadErr
		}
		if !bytes.Equal(rawMode, originalMode) {
			return deployansible.Receipt{}, errors.New("retry_frozen_inputs_changed")
		}
		locked, release, err := deps.remoteLock(operator, lock)
		if err != nil {
			return deployansible.Receipt{}, err
		}
		defer release()
		if err = validateLockedStage(); err != nil {
			return deployansible.Receipt{}, err
		}
		// Native execution keeps the frozen stateRoot lease in its context.
		// Retain the bridge broker's active descriptor separately through action;
		// replacing locked would make RunLocalRetryFailed use the wrong lease.
		_, brokerRelease, err := deps.attach(locked, bootstrapBrokerLockDirectory, lifecycleID(attempt))
		if err != nil {
			return deployansible.Receipt{}, err
		}
		defer brokerRelease()
		if err = validateLockedStage(); err != nil {
			return deployansible.Receipt{}, err
		}
		return action(locked)
	}
	modePath := filepath.Join(attempt, "execution-mode.json")
	modeRaw, modeErr := deps.readPrivate(modePath)
	if os.IsNotExist(modeErr) {
		return deployansible.Receipt{}, errors.New("retry_remote_lifecycle_attachment_unsupported")
	}
	if modeErr != nil {
		return deployansible.Receipt{}, modeErr
	}
	var mode frozenExecution
	if json.Unmarshal(modeRaw, &mode) != nil || mode.Schema != 1 || mode.LockDirectory != lock {
		return deployansible.Receipt{}, errors.New("retry_frozen_execution_invalid")
	}
	if mode.Native {
		if mode.Local || deps.nativeMachine == nil || !deps.nativeMachine(mode.NativeMachineSHA) {
			return deployansible.Receipt{}, errors.New("retry_native_machine_changed")
		}
	}
	if !mode.Local {
		if !mode.Native {
			return deployansible.Receipt{}, errors.New("retry_remote_lifecycle_attachment_unsupported")
		}
		if lock == bootstrapBrokerLockDirectory {
			return deployansible.Receipt{}, errors.New("retry_frozen_execution_invalid")
		}
		return native(mode.OperatorDirectory, modePath, modeRaw)
	}
	if lock != bootstrapBrokerLockDirectory {
		return deployansible.Receipt{}, errors.New("retry_frozen_execution_invalid")
	}
	// Re-read every source through the stricter root-private boundary before the
	// broker attaches its descriptor. No caller socket or fallback lock is used.
	for _, path := range []string{filepath.Join(directory, "job.json"), filepath.Join(directory, "request.json"), modePath} {
		raw, readErr := deps.readRootPrivate(path)
		if readErr != nil {
			return deployansible.Receipt{}, readErr
		}
		original := modeRaw
		if filepath.Base(path) == "job.json" {
			original = jobRaw
		}
		if filepath.Base(path) == "request.json" {
			original = requestRaw
		}
		if !bytes.Equal(raw, original) {
			return deployansible.Receipt{}, errors.New("retry_frozen_inputs_changed")
		}
	}
	frozenRaw, err := deps.readRootPrivate(filepath.Join(attempt, "inventory.frozen.json"))
	if err != nil {
		return deployansible.Receipt{}, err
	}
	var frozen map[string]any
	if json.Unmarshal(frozenRaw, &frozen) != nil {
		return deployansible.Receipt{}, errors.New("retry_frozen_inventory_invalid")
	}
	expected, err := json.Marshal(request.Inventory)
	if err != nil {
		return deployansible.Receipt{}, err
	}
	actual, err := json.Marshal(frozen)
	if err != nil || !bytes.Equal(actual, expected) {
		return deployansible.Receipt{}, errors.New("retry_frozen_inventory_changed")
	}
	target := strings.Split(mode.Target, "|")
	if len(target) != 2 || target[0] == "" || target[1] == "" {
		return deployansible.Receipt{}, errors.New("retry_frozen_target_invalid")
	}
	all, _ := frozen["all"].(map[string]any)
	children, _ := all["children"].(map[string]any)
	bridgeGroup, _ := children["bridge"].(map[string]any)
	hosts, _ := bridgeGroup["hosts"].(map[string]any)
	bridge, _ := hosts["bridge"].(map[string]any)
	if bridge["ansible_host"] != target[0] || bridge["ansible_connection"] != "local" {
		return deployansible.Receipt{}, errors.New("retry_frozen_target_invalid")
	}
	local := true
	p := &installplan.InstallPlan{
		Bridge:                installplan.BridgeConfig{SSHHost: target[0], Address: target[1]},
		ControllerLocal:       &local,
		ControllerLocalTarget: mode.Target,
	}
	if !deps.machine(p) {
		return deployansible.Receipt{}, errors.New("retry_frozen_machine_changed")
	}
	if !filepath.IsAbs(mode.OperatorDirectory) || filepath.Clean(mode.OperatorDirectory) != mode.OperatorDirectory ||
		filepath.Base(mode.OperatorDirectory) != "operator" ||
		filepath.Dir(mode.OperatorDirectory) != filepath.Dir(filepath.Dir(attempt)) {
		return deployansible.Receipt{}, errors.New("retry_original_operator_lock_required_resume_full_apply")
	}
	operator, operatorRelease, err := deps.operator(ctx, mode.OperatorDirectory)
	if err != nil {
		return deployansible.Receipt{}, err
	}
	defer operatorRelease()
	for _, input := range []struct {
		path     string
		original []byte
	}{{filepath.Join(directory, "request.json"), requestRaw}, {filepath.Join(directory, "job.json"), jobRaw}, {modePath, modeRaw}, {filepath.Join(attempt, "inventory.frozen.json"), frozenRaw}} {
		raw, readErr := deps.readRootPrivate(input.path)
		if readErr != nil {
			return deployansible.Receipt{}, readErr
		}
		if !bytes.Equal(raw, input.original) {
			return deployansible.Receipt{}, errors.New("retry_frozen_inputs_changed")
		}
	}
	if !deps.machine(p) {
		return deployansible.Receipt{}, errors.New("retry_frozen_machine_changed")
	}
	locked, release, err := deps.attach(operator, bootstrapBrokerLockDirectory, lifecycleID(attempt))
	if err != nil {
		return deployansible.Receipt{}, err
	}
	defer release()
	if err = validateLockedStage(); err != nil {
		return deployansible.Receipt{}, err
	}
	return action(locked)
}

func validateBootstrapRetryOperatorDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "operator" {
		return errors.New("retry_original_operator_lock_required_resume_full_apply")
	}
	for _, directory := range []string{path, filepath.Dir(path)} {
		info, err := os.Lstat(directory)
		if err != nil {
			return err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Geteuid()) || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			return errors.New("retry_operator_lock_invalid")
		}
	}
	for candidate := path; ; candidate = filepath.Dir(candidate) {
		info, err := os.Lstat(candidate)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("retry_operator_lock_invalid")
		}
		if filepath.Dir(candidate) == candidate {
			break
		}
	}
	return nil
}

func validNativeRetryMachine(expected string) bool {
	if os.Geteuid() != 0 {
		return false
	}
	machine, err := readNativeAdoptionFile("/etc/machine-id", nil)
	if err != nil || len(strings.TrimSpace(string(machine))) != 32 {
		return false
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.TrimSpace(string(machine))))) == expected
}
