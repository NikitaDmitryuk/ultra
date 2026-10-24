package deployansible

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
)

// ExecutionFence survives controller/process death. Only a matching normal
// completion can retire it; PID exit and free advisory locks are not evidence
// that remote commands stopped.
type ExecutionFence struct {
	SchemaVersion   int    `json:"schema_version"`
	Generation      string `json:"generation"`
	Operation       string `json:"operation"`
	JobDirectory    string `json:"job_directory"`
	JobSHA256       string `json:"job_sha256"`
	RequestSHA256   string `json:"request_sha256"`
	BundleSHA256    string `json:"bundle_sha256"`
	InventorySHA256 string `json:"inventory_sha256"`
	Attempt         int    `json:"attempt"`
}

var ErrExecutionFenced = errors.New("execution_uncertain_reconciliation_required")

// Fixed production namespace, independent of frozen requests and job paths.
// Package tests replace this resolver with an isolated private fixture.
var executionFenceDirectory = productionExecutionFenceDirectory

func productionExecutionFenceDirectory(string) string {
	root, err := ExpectedLocalExecutionState()
	if err != nil {
		return ""
	}
	return root
}

func executionReadOnly(operation string) bool {
	switch operation {
	case "inspect-bootstrap",
		"status-automation":
		return true
	}
	return false
}

func executionHash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

func executionBinding(directory string) (ExecutionFence, error) {
	raw, err := readRetryPrivate(filepath.Join(directory, "job.json"))
	if err != nil {
		return ExecutionFence{}, err
	}
	var job struct {
		Operation string `json:"operation"`
		Request   string `json:"request_sha256"`
		Attempt   int    `json:"attempt"`
	}
	if json.Unmarshal(raw, &job) != nil {
		return ExecutionFence{}, ErrExecutionFenced
	}
	request, err := readRetryPrivate(filepath.Join(directory, "request.json"))
	if err != nil || executionHash(request) != job.Request {
		return ExecutionFence{}, ErrExecutionFenced
	}
	h := sha256.New()
	err = filepath.WalkDir(filepath.Join(directory, "bundle"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return ErrExecutionFenced
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		name, err := filepath.Rel(filepath.Join(directory, "bundle"), path)
		if err != nil {
			return err
		}
		h.Write([]byte(filepath.ToSlash(name)))
		h.Write([]byte{0})
		h.Write([]byte(executionHash(raw)))
		h.Write([]byte{'\n'})
		return nil
	})
	if err != nil {
		return ExecutionFence{}, err
	}
	if job.Attempt == 0 {
		job.Attempt = 1
	}
	return ExecutionFence{
		SchemaVersion:   1,
		Operation:       job.Operation,
		JobDirectory:    directory,
		JobSHA256:       executionHash(raw),
		RequestSHA256:   job.Request,
		BundleSHA256:    hex.EncodeToString(h.Sum(nil)),
		InventorySHA256: executionHash(request),
		Attempt:         job.Attempt,
	}, nil
}

func executionRoot(directory string) (string, error) {
	return prepareExecutionRoot(executionFenceDirectory(directory))
}

func prepareExecutionRoot(root string) (string, error) {
	if !executionNamespaceFixture() {
		if err := requireConfiguredExecutionState(); err != nil {
			return "", err
		}
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || !ownedByProcess(info) || info.Mode().Perm()&0077 != 0 {
		return "", ErrExecutionFenced
	}
	return root, nil
}

func inspectExecutionFence(root string) (*ExecutionFence, error) {
	raw, err := readRetryPrivate(filepath.Join(root, "execution-fence.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrExecutionFenced
	}
	var fence ExecutionFence
	if json.Unmarshal(raw, &fence) != nil || fence.SchemaVersion != 1 || len(fence.Generation) != 32 ||
		!filepath.IsAbs(fence.JobDirectory) {
		return nil, ErrExecutionFenced
	}
	return &fence, nil
}

// InspectExecutionFence reads the fixed controller namespace, without dispatch.
func InspectExecutionFence() (*ExecutionFence, error) {
	root, err := executionRoot("")
	if err != nil {
		return nil, err
	}
	fence, err := inspectExecutionFence(root)
	if err == nil && fence != nil {
		// Retain a late manager timeout observation after dispatcher death. This
		// is diagnostic only; it never authorizes dispatch or retires the fence.
		limitErr := observeExecutionRuntimeLimit(*fence)
		if limitErr != nil && !errors.Is(limitErr, errExecutionRuntimeLimit) {
			return fence, limitErr
		}
	}
	return fence, err
}

func executionAdmission(directory string) error {
	root, err := executionRoot(directory)
	if err != nil {
		return err
	}
	lock, err := controllerLock(filepath.Join(root, "execution-admission.lock"))
	if err != nil {
		return ErrExecutionFenced
	}
	defer lock.Close() //nolint:errcheck
	return checkExecutionAdmission(root)
}

// Adopt uncertain legacy jobs already in the canonical queue namespace before
// admitting any newer job. An old failed receipt is not proof of SSH quiescence.
func checkExecutionAdmission(root string) error {
	fence, err := inspectExecutionFence(root)
	if err != nil {
		return err
	}
	if fence != nil {
		return ErrExecutionFenced
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		directory := filepath.Join(root, entry.Name())
		if _, err := os.Lstat(filepath.Join(directory, "job.json")); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return ErrExecutionFenced
		}
		raw, err := readRetryPrivate(filepath.Join(directory, "receipt.json"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return ErrExecutionFenced
		}
		var receipt struct {
			State string `json:"state"`
		}
		if json.Unmarshal(raw, &receipt) != nil {
			return ErrExecutionFenced
		}
		if receipt.State == "succeeded" || completedExecution(directory) || preparedRetryExecution(directory) {
			continue
		}
		// A retired failed generation is preserved evidence, never a live claim.
		if abandoned, abandonErr := savedAbandonment(directory); abandonErr != nil || abandoned != nil {
			if abandonErr != nil {
				return ErrExecutionFenced
			}
			continue
		}
		binding, err := executionBinding(directory)
		if err != nil {
			return ErrExecutionFenced
		}
		if executionReadOnly(binding.Operation) {
			continue
		}
		if err = persistExecutionFence(root, &binding); err != nil {
			return err
		}
		return ErrExecutionFenced
	}
	return nil
}

func persistExecutionFence(root string, binding *ExecutionFence) error {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	binding.Generation = hex.EncodeToString(nonce)
	raw, err := json.Marshal(binding)
	if err != nil {
		return err
	}
	if err = writePrivate(filepath.Join(root, "execution-fence.json"), raw); err != nil {
		return err
	}
	return syncDirectory(root)
}

func beginExecution(directory string) (*ExecutionFence, error) {
	namespace := executionFenceDirectory(directory)
	binding, err := executionBinding(directory)
	if err != nil {
		return nil, err
	}
	if executionReadOnly(binding.Operation) {
		return nil, nil
	}
	if abandoned, abandonErr := savedAbandonment(directory); abandonErr != nil || abandoned != nil {
		if abandonErr != nil {
			return nil, ErrExecutionFenced
		}
		return nil, ErrExecutionAbandoned
	}
	if !executionNamespaceFixture() {
		if err = executionContainmentPreflight(); err != nil {
			return nil, err
		}
	}
	root, err := prepareExecutionRoot(namespace)
	if err != nil {
		return nil, err
	}
	lock, err := controllerLock(filepath.Join(root, "execution-admission.lock"))
	if err != nil {
		return nil, ErrExecutionFenced
	}
	defer lock.Close() //nolint:errcheck
	if err = checkExecutionAdmission(root); err != nil {
		return nil, err
	}
	uncertainLegacy := false
	// Legacy running/interrupted jobs are recorded but never redispatched.
	if raw, readErr := readRetryPrivate(filepath.Join(directory, "receipt.json")); readErr == nil {
		var receipt struct {
			State string `json:"state"`
		}
		if json.Unmarshal(raw, &receipt) != nil {
			return nil, ErrExecutionFenced
		}
		if receipt.State == "running" || receipt.State == "failed" {
			uncertainLegacy = !completedExecution(directory)
		}
		if receipt.State == "succeeded" || (receipt.State == "failed" && completedExecution(directory)) {
			return nil, nil
		}
	} else if !os.IsNotExist(readErr) {
		return nil, ErrExecutionFenced
	}
	// A lost receipt cannot erase the durable per-generation dispatch claim.
	// Explicit retries advance job.json first, so an older attempt's claim differs.
	claims, claimErr := filepath.Glob(filepath.Join(directory, "execution-dispatch-*.json"))
	if claimErr != nil {
		return nil, ErrExecutionFenced
	}
	for _, path := range claims {
		raw, readErr := readRetryPrivate(path)
		if readErr != nil {
			return nil, ErrExecutionFenced
		}
		var prior ExecutionFence
		if json.Unmarshal(raw, &prior) != nil {
			return nil, ErrExecutionFenced
		}
		prior.Generation = ""
		if prior == binding {
			uncertainLegacy = true
		}
	}
	if err = persistExecutionFence(root, &binding); err != nil {
		return nil, err
	}
	if uncertainLegacy {
		return nil, ErrExecutionFenced
	}
	return &binding, nil
}

// ReconcileExecutionFence accepts only the exact generation and a controller
// completion produced after normal Ansible success and local worker cleanup.
// It cannot reconcile an uncertain transport failure or prove remote quiescence.
func ReconcileExecutionFence(expected ExecutionFence) error {
	root, err := executionRoot(expected.JobDirectory)
	if err != nil {
		return err
	}
	lock, err := controllerLock(filepath.Join(root, "execution-admission.lock"))
	if err != nil {
		return ErrExecutionFenced
	}
	defer lock.Close() //nolint:errcheck
	current, err := inspectExecutionFence(root)
	if err != nil || current == nil || *current != expected {
		return ErrExecutionFenced
	}
	if err = observeExecutionRuntimeLimit(expected); err != nil {
		return err
	}
	if err = validateExecutionCompletion(expected); err != nil {
		return err
	}
	if err = reconcileExecutionContainment(expected); err != nil {
		return err
	}
	if err = os.Remove(filepath.Join(root, "execution-fence.json")); err != nil {
		return err
	}
	return syncDirectory(root)
}

func validateExecutionCompletion(expected ExecutionFence) error {
	if err := validateExecutionContainment(expected); err != nil {
		return err
	}
	return validateExecutionTerminal(expected)
}

// validateExecutionTerminal reads only frozen inputs and normal terminal proof.
// It never observes systemd, creates cleanup evidence or retires a fence.
func validateExecutionTerminal(expected ExecutionFence) error {
	binding, err := executionBinding(expected.JobDirectory)
	if err != nil {
		return ErrExecutionFenced
	}
	binding.Generation = expected.Generation
	if binding != expected {
		return ErrExecutionFenced
	}
	return validateExecutionReceipt(expected)
}

// validateExecutionReceipt checks exact normal outcome evidence only. Callers
// must independently establish their live or historical frozen input binding.
func validateExecutionReceipt(expected ExecutionFence) error {
	if err := savedExecutionRuntimeLimit(expected); err != nil {
		return err
	}
	raw, err := readRetryPrivate(filepath.Join(expected.JobDirectory, "execution-completion.json"))
	if err != nil {
		return ErrExecutionFenced
	}
	var complete struct {
		Outcome        string         `json:"outcome"`
		TerminalSHA256 string         `json:"terminal_sha256"`
		Fence          ExecutionFence `json:"fence"`
		ReceiptSHA256  string         `json:"receipt_sha256"`
		LocalCleanup   bool           `json:"local_cleanup"`
	}
	if json.Unmarshal(raw, &complete) != nil || !reflect.DeepEqual(complete.Fence, expected) || !complete.LocalCleanup {
		return ErrExecutionFenced
	}
	raw, err = readRetryPrivate(filepath.Join(expected.JobDirectory, "receipt.json"))
	if err != nil || executionHash(raw) != complete.ReceiptSHA256 {
		return ErrExecutionFenced
	}
	var receipt struct {
		State      string `json:"state"`
		Generation string `json:"execution_generation"`
		Code       string `json:"code"`
		ExitCode   int    `json:"exit_code"`
	}
	if json.Unmarshal(raw, &receipt) != nil || receipt.Generation != expected.Generation {
		return ErrExecutionFenced
	}

	if receipt.State == "succeeded" {
		return nil
	}
	if receipt.State != "failed" || complete.Outcome != "failed" || receipt.Code != "ansible_failed" || receipt.ExitCode != 2 {
		return ErrExecutionFenced
	}
	proofRaw, err := readRetryPrivate(filepath.Join(expected.JobDirectory, "execution-terminal-"+expected.Generation+".json"))
	if err != nil || executionHash(proofRaw) != complete.TerminalSHA256 {
		return ErrExecutionFenced
	}
	var proof struct {
		Fence            ExecutionFence `json:"fence"`
		Outcome          string         `json:"outcome"`
		ContactedHosts   int            `json:"contacted_hosts"`
		PendingTasks     int            `json:"pending_tasks"`
		UnreachableHosts int            `json:"unreachable_hosts"`
		UnmanagedAsync   bool           `json:"unmanaged_async"`
	}
	if json.Unmarshal(proofRaw, &proof) != nil || proof.Fence != expected || proof.Outcome != "failed" || proof.ContactedHosts <= 0 ||
		proof.PendingTasks != 0 ||
		proof.UnreachableHosts != 0 ||
		proof.UnmanagedAsync {
		return ErrExecutionFenced
	}
	return nil
}

func completedExecution(directory string) bool {
	raw, err := readRetryPrivate(filepath.Join(directory, "execution-completion.json"))
	if err != nil {
		return false
	}
	var complete struct {
		Fence ExecutionFence `json:"fence"`
	}
	if json.Unmarshal(raw, &complete) != nil || complete.Fence.JobDirectory != directory {
		return false
	}
	return validateExecutionCompletion(complete.Fence) == nil
}
