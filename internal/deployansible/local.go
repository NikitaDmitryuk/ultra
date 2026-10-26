package deployansible

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
)

type operationLeaseKey struct{}
type operationLease struct {
	directory string
	file      *os.File
	active    atomic.Bool
	run       sync.Mutex
}

// WithOperationLock holds one lease across inspection, application and verification.
// Callers must pass the returned context to every RunLocal stage.
func WithOperationLock(ctx context.Context, directory string) (context.Context, func(), error) {
	if !filepath.IsAbs(directory) {
		return ctx, nil, errors.New("absolute operation lock directory required")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || !ownedByProcess(info) || info.Mode().Perm()&0077 != 0 {
		return ctx, nil, errors.New("private operation lock directory required")
	}
	admission, fenceErr := recoveryAdmission(directory)
	if fenceErr != nil {
		return ctx, nil, fenceErr
	}
	defer admission()
	lock, err := controllerLock(filepath.Join(directory, "infrastructure.lock"))
	if err != nil {
		return ctx, nil, err
	}
	lease := &operationLease{directory: directory, file: lock}
	lease.active.Store(true)
	return context.WithValue(ctx, operationLeaseKey{}, lease), func() {
		lease.run.Lock()
		defer lease.run.Unlock()
		if lease.active.Swap(false) {
			_ = lock.Close()
		}
	}, nil
}

// RunLocal runs an operator-owned, fixed operation. It is deliberately unavailable
// through the relay socket: inventory and source paths are trusted operator inputs.
// Reusing a directory resumes exactly the same frozen inputs after interruption.
func RunLocal(
	ctx context.Context,
	operation string,
	inventory, variables map[string]any,
	directory, python, executable string,
) (Receipt, error) {
	return runLocal(ctx, operation, inventory, variables, directory, python, executable, false, "")
}

// RunLocalRetryFailed is an explicit operator retry. Successful cached stages stay
// cached; terminal failures are archived before a new attempt can execute.
// It is not used by typed workers or automatic upgrades.
func RunLocalRetryFailed(
	ctx context.Context,
	operation string,
	inventory, variables map[string]any,
	directory, python, executable string,
) (Receipt, error) {
	if !localRetryOperation(operation, variables) {
		return Receipt{}, errors.New("retry_bootstrap_operation_required")
	}
	if _, ok := ctx.Value(operationLeaseKey{}).(*operationLease); !ok {
		return Receipt{}, errors.New("retry requires operation lease")
	}
	return runLocal(ctx, operation, inventory, variables, directory, python, executable, true, "")
}

func localRetryOperation(operation string, variables map[string]any) bool {
	if operation == "ingress" {
		switch variables["ultra_ingress_action"] {
		case "prepare", "activate", "adopt", "retire-experiment":
			return true
		default:
			return false
		}
	}
	if bootstrapRetryOperation(operation) {
		return true
	}
	return false
}

// localDispatchFailure reports a failure that happened before the controller
// completed. A zero Receipt used to erase the reason, so callers printed an empty
// stage/node/code triple. code is the stable guard identifier; err is preserved.
func localDispatchFailure(code string, err error) (Receipt, error) {
	if len(code) > 64 {
		code = code[:64]
	}
	return Receipt{Diagnostic: Diagnostic{Stage: "dispatch", Node: "local", Code: code}}, err
}

// dispatchCode bounds an error that carries no stable identifier of its own. The
// identifier form is preserved so execution_uncertain_reconciliation_required
// stays recognizable to callers that match on it.
func dispatchCode(err error) string {
	if err == nil {
		return "dispatch_failed"
	}
	code := err.Error()
	if len(code) > 64 {
		code = code[:64]
	}
	return code
}

// runLocal reports which local guard stopped the operation. A guard that fails
// before the controller runs leaves no receipt, and an empty stage/node/code
// triple reads exactly like an Ansible task failure.
func runLocal(
	ctx context.Context,
	operation string,
	inventory, variables map[string]any,
	directory, python, executable string,
	retry bool,
	source string,
) (Receipt, error) {
	allowed := map[string]bool{
		"bootstrap-recovery-tools":     true,
		"retain-artifacts":             true,
		"resume-schedules":             true,
		"rollback-adoption":            true,
		"reserve-rolledback-bootstrap": true,
		"resume-adoption":              true,
		"lifecycle":                    true,
		"prepare-controller":           true,
		"inspect-bootstrap":            true,
		"status-automation":            true,
		"resume-automation":            true,
		"configure-bot":                true,
		"configure-exit-operator":      true,
		"ingress":                      true,
		"bootstrap":                    true,
		"bootstrap-postgres":           true,
		"bootstrap-exit":               true,
		"bootstrap-bridge":             true,
		"bootstrap-automation":         true,
		"verify-bootstrap-automation":  true,
		"reconcile":                    true,
		"adopt":                        true,
		"adopt-topology":               true,
		"restore":                      true,
		"restore-database":             true,
		"restore-peer":                 true,
		"domain-cutover":               true,
		"backend-domain":               true,
	}
	if !allowed[operation] || !filepath.IsAbs(directory) || !filepath.IsAbs(python) || !filepath.IsAbs(executable) {
		return localDispatchFailure("operation_not_allowed", errors.New("invalid local operation or executor paths"))
	}
	parent := filepath.Dir(directory)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return localDispatchFailure("lock_directory_unavailable", err)
	}
	lockDirectory := parent
	if lease, ok := ctx.Value(operationLeaseKey{}).(*operationLease); ok {
		lockDirectory = lease.directory
	}
	if configured, ok := variables["ultra_lock_directory"].(string); ok {
		if !filepath.IsAbs(configured) {
			return localDispatchFailure("lock_directory_not_absolute", errors.New("absolute operation lock directory required"))
		}
		lockDirectory = configured
	}
	lockInfo, err := os.Lstat(lockDirectory)
	if err != nil || !lockInfo.IsDir() || !ownedByProcess(lockInfo) || lockInfo.Mode().Perm()&0077 != 0 {
		return localDispatchFailure("lock_directory_insecure", errors.New("private operation lock directory required"))
	}
	if lease, ok := ctx.Value(operationLeaseKey{}).(*operationLease); ok {
		lease.run.Lock()
		defer lease.run.Unlock()
	}
	admission, fenceErr := recoveryAdmission(lockDirectory)
	if fenceErr != nil {
		return localDispatchFailure("recovery_admission_refused", fenceErr)
	}
	defer admission()
	if lease, ok := ctx.Value(operationLeaseKey{}).(*operationLease); ok {
		if !lease.active.Load() || lease.directory != lockDirectory {
			return localDispatchFailure("operation_lease_mismatch", errors.New("operation lease directory mismatch"))
		}
	} else {
		lock, err := controllerLock(filepath.Join(lockDirectory, "infrastructure.lock"))
		if err != nil {
			return localDispatchFailure("infrastructure_lock_busy", err)
		}
		defer lock.Close() //nolint:errcheck
	}
	admission() // The infrastructure lease now tracks this admitted stage.
	raw, err := localExecutionRequest(ctx, operation, directory, inventory, variables)
	if source != "" && err == nil {
		raw, err = pinnedLocalExecutionRequest(ctx, operation, directory, source, inventory, variables)
	}
	if err != nil {
		return localDispatchFailure("request_unencodable", err)
	}

	// codeql[go/weak-sensitive-data-hashing] This deterministic digest binds a frozen operation request for idempotency; it is not used to authenticate a password or stored as a credential verifier.
	hash := sha256.Sum256(raw)
	id := hex.EncodeToString(hash[:])
	export := Export
	if source != "" {
		export, err = pinnedBootstrapExporter(source, directory, operation, raw)
		if err != nil {
			return localDispatchFailure("bootstrap_exporter_unpinned", err)
		}
	}
	if receipt, cached, cacheErr := collectedRetentionResult(operation, directory, raw, id); cached {
		return receipt, cacheErr
	}
	if err = prepareLocalOperation(directory, operation, raw, id, export); err != nil {
		return localDispatchFailure("job_preparation_failed", err)
	}
	if retry {
		if !executionReadOnly(operation) {
			if err = executionAdmission(directory); err != nil {
				return localDispatchFailure("execution_admission_refused", err)
			}
			if prior, readErr := os.ReadFile(filepath.Join(directory, "receipt.json")); readErr == nil {
				var state struct {
					State string `json:"state"`
				}
				if json.Unmarshal(prior, &state) != nil ||
					(state.State != "succeeded" && !completedExecution(directory) && !preparedRetryExecution(directory)) {
					_, _ = beginExecutionContext(ctx, directory) // Adopt a legacy uncertain mutator without dispatch.
					return localDispatchFailure("execution_uncertain_reconciliation_required", ErrExecutionFenced)
				}
			}
			if completedExecution(directory) {
				if err = prepareRetryExecution(directory); err != nil {
					return localDispatchFailure("retry_preparation_failed", err)
				}
			}
		}
		if err = retryFailedLocalAttempt(directory); err != nil {
			return localDispatchFailure("retry_archive_failed", err)
		}
	}
	fence, fenceErr := beginExecutionContext(ctx, directory)
	if fenceErr != nil {
		return localDispatchFailure(dispatchCode(fenceErr), fenceErr)
	}
	bundle := filepath.Join(directory, "bundle")
	command := exec.CommandContext(
		ctx,
		python,
		filepath.Join(bundle, "controller.py"),
		"--job",
		directory,
		"--bundle",
		bundle,
		"--executable",
		executable,
	)
	isolateCommand(command)
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	if fence != nil {
		command.Env = append(command.Env, "ULTRA_EXECUTION_GENERATION="+fence.Generation)
	}
	runErr := runContainedController(ctx, command, fence)
	if fence != nil {
		if closeErr := reconcileControllerExecution(*fence, runErr); closeErr != nil && runErr == nil {
			return localDispatchFailure("execution_drain_unverified", closeErr)
		}
	}
	data, err := os.ReadFile(filepath.Join(directory, "receipt.json"))
	var receipt Receipt
	if err != nil || json.Unmarshal(data, &receipt) != nil {
		return localDispatchFailure("local_receipt_unavailable", errors.New("local operation receipt unavailable"))
	}
	if runErr != nil || receipt.State != "succeeded" {
		if fence != nil && errors.Is(observeExecutionRuntimeLimit(*fence), errExecutionRuntimeLimit) {
			receipt.Diagnostic = Diagnostic{Stage: "execute", Node: "local", Code: "execution_runtime_limit"}
			return receipt, errExecutionRuntimeLimit
		}
		if receipt.Diagnostic == (Diagnostic{}) {
			receipt.Diagnostic = Diagnostic{Stage: "execute", Node: "local", Code: dispatchCode(runErr)}
		}
		return receipt, fmt.Errorf("ansible operation failed: %s", receipt.Code)
	}
	return receipt, nil
}
