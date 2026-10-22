package deployansible

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
	"syscall"
)

// RetryFrozenBootstrap resumes a fixed local bootstrap stage from its original
// request and bundled controller. The caller must hold that request's lease.
// No caller-supplied inventory, role, or command is accepted here.
// RetryFrozenBootstrapWithLock acquires only the lease named in the original
// frozen request. The CLI cannot substitute a different lock directory.
func RetryFrozenBootstrapWithLock(ctx context.Context, directory, python, executable string) (Receipt, error) {
	raw, err := readRetryPrivate(filepath.Join(directory, "request.json"))
	if err != nil {
		return Receipt{}, err
	}
	var request struct {
		Variables map[string]any `json:"variables"`
	}
	if json.Unmarshal(raw, &request) != nil {
		return Receipt{}, errors.New("retry_inputs_invalid")
	}
	jobRaw, err := readRetryPrivate(filepath.Join(directory, "job.json"))
	if err != nil {
		return Receipt{}, err
	}
	var job struct {
		Operation string `json:"operation"`
		Hash      string `json:"request_sha256"`
	}
	hash := sha256.Sum256(raw)
	if json.Unmarshal(jobRaw, &job) != nil || job.Hash != hex.EncodeToString(hash[:]) || !bootstrapRetryOperation(job.Operation) {
		return Receipt{}, errors.New("retry_inputs_invalid")
	}
	lockDirectory, ok := request.Variables["ultra_lock_directory"].(string)
	if !ok || !filepath.IsAbs(lockDirectory) {
		return Receipt{}, errors.New("retry_frozen_lock_directory_required")
	}
	if filepath.Clean(lockDirectory) == "/var/lib/ultra-ansible" {
		return Receipt{}, errors.New("retry_local_broker_attachment_required")
	}
	locked, release, err := WithOperationLock(ctx, lockDirectory)
	if err != nil {
		return Receipt{}, err
	}
	defer release()
	return RetryFrozenBootstrap(locked, directory, python, executable)
}

func RetryFrozenBootstrap(ctx context.Context, directory, python, executable string) (Receipt, error) {
	raw, err := readRetryPrivate(filepath.Join(directory, "request.json"))
	if err != nil {
		return Receipt{}, err
	}
	jobRaw, err := readRetryPrivate(filepath.Join(directory, "job.json"))
	if err != nil {
		return Receipt{}, err
	}
	var request struct {
		Inventory map[string]any `json:"inventory"`
		Variables map[string]any `json:"variables"`
	}
	var job struct {
		Operation string `json:"operation"`
	}
	if json.Unmarshal(raw, &request) != nil || json.Unmarshal(jobRaw, &job) != nil {
		return Receipt{}, errors.New("retry_inputs_invalid")
	}
	if !bootstrapRetryOperation(job.Operation) {
		return Receipt{}, errors.New("retry_bootstrap_operation_required")
	}
	return RunLocalRetryFailed(ctx, job.Operation, request.Inventory, request.Variables, directory, python, executable)
}

func bootstrapRetryOperation(operation string) bool {
	switch operation {
	case "stage-recovery-preparation",
		"initialize-recovery-monitor",
		"inspect-bootstrap",
		"bootstrap",
		"bootstrap-recovery-inspect",
		"bootstrap-recovery-tools",
		"bootstrap-postgres",
		"bootstrap-exit",
		"bootstrap-bridge",
		"ingress",
		"configure-bot",
		"bootstrap-automation",
		"reserve-rolledback-bootstrap":
		return true
	default:
		return false
	}
}

func readRetryPrivate(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close() //nolint:errcheck
	info, err := file.Stat()
	if err != nil || !ownedByProcess(info) {
		return nil, errors.New("retry_private_file_required")
	}
	return readInput(file, 1<<20, true)
}

func retryAttempt(value any) (int, error) {
	if value == nil {
		return 1, nil
	}
	n, ok := value.(float64)
	if !ok || n < 1 || n > 1000 || n != float64(int(n)) {
		return 0, errors.New("retry_attempt_invalid")
	}
	return int(n), nil
}

// A retry authorization is published while the old generation still matches its
// exact callback/cleanup proof, before advancing job.json. A crash after the
// rename can therefore finish that metadata transaction without adopting an
// uncertain new execution. It never authorizes replay of a dispatched generation.
type localRetryPreparation struct {
	Schema           int            `json:"schema"`
	OriginalJob      []byte         `json:"original_job"`
	NextJobSHA256    string         `json:"next_job_sha256"`
	ReceiptSHA256    string         `json:"receipt_sha256"`
	CompletionSHA256 string         `json:"completion_sha256"`
	Fence            ExecutionFence `json:"fence"`
}

var syncLocalRetryDirectory = syncDirectory

func retryPreparationPath(directory string, attempt int) string {
	return filepath.Join(directory, fmt.Sprintf("retry-preparation-%d.json", attempt))
}

func prepareRetryExecution(directory string) error {
	if !completedExecution(directory) {
		return ErrExecutionFenced
	}
	jobRaw, err := readRetryPrivate(filepath.Join(directory, "job.json"))
	if err != nil {
		return err
	}
	receiptRaw, err := readRetryPrivate(filepath.Join(directory, "receipt.json"))
	if err != nil {
		return err
	}
	completeRaw, err := readRetryPrivate(filepath.Join(directory, "execution-completion.json"))
	if err != nil {
		return err
	}
	var complete struct {
		Fence ExecutionFence `json:"fence"`
	}
	var receipt struct {
		State string `json:"state"`
	}
	if json.Unmarshal(receiptRaw, &receipt) != nil {
		return ErrExecutionFenced
	}
	if receipt.State != "failed" {
		return nil
	}
	var job map[string]any
	if json.Unmarshal(completeRaw, &complete) != nil || json.Unmarshal(jobRaw, &job) != nil {
		return ErrExecutionFenced
	}
	old, err := retryAttempt(job["attempt"])
	if err != nil || old != complete.Fence.Attempt {
		return ErrExecutionFenced
	}
	job["attempt"] = old + 1
	next, err := json.Marshal(job)
	if err != nil {
		return err
	}
	intent := localRetryPreparation{1, jobRaw, executionHash(next), executionHash(receiptRaw), executionHash(completeRaw), complete.Fence}
	raw, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	path := retryPreparationPath(directory, old)
	if saved, e := readRetryPrivate(path); e == nil {
		if !bytes.Equal(saved, raw) {
			return ErrExecutionFenced
		}
		return nil
	} else if !os.IsNotExist(e) {
		return e
	}
	file, err := os.CreateTemp(directory, ".retry-preparation-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name) //nolint:errcheck
	if _, err = file.Write(raw); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Link(name, path); err != nil {
		return err
	}
	if err = os.Remove(name); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func preparedRetryExecution(directory string) bool {
	jobRaw, err := readRetryPrivate(filepath.Join(directory, "job.json"))
	if err != nil {
		return false
	}
	receiptRaw, err := readRetryPrivate(filepath.Join(directory, "receipt.json"))
	if err != nil {
		return false
	}
	var job, receipt map[string]any
	if json.Unmarshal(jobRaw, &job) != nil || json.Unmarshal(receiptRaw, &receipt) != nil || receipt["state"] != "failed" {
		return false
	}
	old, err := retryAttempt(receipt["attempt"])
	if err != nil {
		return false
	}
	current, err := retryAttempt(job["attempt"])
	if err != nil || current != old+1 {
		return false
	}
	raw, err := readRetryPrivate(retryPreparationPath(directory, old))
	if err != nil {
		return false
	}
	var intent localRetryPreparation
	if json.Unmarshal(raw, &intent) != nil || intent.Schema != 1 || intent.NextJobSHA256 != executionHash(jobRaw) ||
		intent.ReceiptSHA256 != executionHash(receiptRaw) ||
		intent.Fence.Attempt != old ||
		executionHash(intent.OriginalJob) != intent.Fence.JobSHA256 {
		return false
	}
	complete, err := readRetryPrivate(filepath.Join(directory, "execution-completion.json"))
	if err != nil || executionHash(complete) != intent.CompletionSHA256 {
		return false
	}
	var saved struct {
		Fence          ExecutionFence `json:"fence"`
		ReceiptSHA256  string         `json:"receipt_sha256"`
		LocalCleanup   bool           `json:"local_cleanup"`
		Outcome        string         `json:"outcome"`
		TerminalSHA256 string         `json:"terminal_sha256"`
	}
	if json.Unmarshal(complete, &saved) != nil || saved.Fence != intent.Fence || saved.ReceiptSHA256 != intent.ReceiptSHA256 ||
		!saved.LocalCleanup {
		return false
	}
	if saved.Outcome != "failed" || saved.TerminalSHA256 == "" {
		return false
	}
	terminal, err := readRetryPrivate(filepath.Join(directory, "execution-terminal-"+intent.Fence.Generation+".json"))
	if err != nil || executionHash(terminal) != saved.TerminalSHA256 {
		return false
	}
	// Recompute every current bundle/request binding, substituting ONLY the
	// write-ahead original job bytes and attempt already authenticated above.
	binding, err := executionBinding(directory)
	if err != nil {
		return false
	}
	binding.JobSHA256 = executionHash(intent.OriginalJob)
	binding.Attempt = old
	binding.Generation = intent.Fence.Generation
	if binding != intent.Fence {
		return false
	}
	var original map[string]any
	if json.Unmarshal(intent.OriginalJob, &original) != nil {
		return false
	}
	original["attempt"] = old + 1
	next, err := json.Marshal(original)
	if err != nil || !bytes.Equal(next, jobRaw) {
		return false
	}
	archived, err := readRetryPrivate(filepath.Join(directory, "history", fmt.Sprintf("attempt-%d.json", old)))
	return err == nil && bytes.Equal(archived, receiptRaw)
}

// Caller holds the matching infrastructure lease. Archive, advance, and remove
// are deliberately ordered: every interruption retains a recoverable failure.
func retryFailedLocalAttempt(directory string) error {
	return retryFailedLocalAttemptWith(directory, syncLocalRetryDirectory)
}

func retryFailedLocalAttemptWith(directory string, syncDir func(string) error) error {
	receiptPath := filepath.Join(directory, "receipt.json")
	raw, err := readRetryPrivate(receiptPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var receipt, job map[string]any
	jobPath := filepath.Join(directory, "job.json")
	jobRaw, err := readRetryPrivate(jobPath)
	if err != nil {
		return err
	}
	if json.Unmarshal(raw, &receipt) != nil || json.Unmarshal(jobRaw, &job) != nil {
		return errors.New("retry_metadata_invalid")
	}
	request, err := readRetryPrivate(filepath.Join(directory, "request.json"))
	if err != nil {
		return err
	}
	hash := sha256.Sum256(request)
	if job["request_sha256"] != hex.EncodeToString(hash[:]) || receipt["request_sha256"] != job["request_sha256"] ||
		receipt["binary_sha256"] != job["binary_sha256"] ||
		receipt["operation"] != job["operation"] ||
		receipt["schema_version"] != job["schema_version"] ||
		job["schema_version"] != float64(1) {
		return errors.New("retry_job_receipt_conflict")
	}
	binary, ok := job["binary_sha256"].(string)
	decoded, decodeErr := hex.DecodeString(binary)
	if !ok || decodeErr != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != binary {
		return errors.New("retry_binary_identity_invalid")
	}
	old, err := retryAttempt(receipt["attempt"])
	if err != nil {
		return err
	}
	current, err := retryAttempt(job["attempt"])
	if err != nil {
		return err
	}
	if receipt["state"] != "failed" {
		if current != old {
			return errors.New("retry_attempt_conflict")
		}
		if receipt["state"] != "succeeded" && receipt["state"] != "running" {
			return errors.New("retry_receipt_state_invalid")
		}
		return nil
	}
	if old >= 1000 || (current != old && current != old+1) {
		return errors.New("retry_attempt_conflict")
	}
	history := filepath.Join(directory, "history")
	if err = os.Mkdir(history, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(history)
	if err != nil || !info.IsDir() || !ownedByProcess(info) || info.Mode().Perm()&0077 != 0 {
		return errors.New("retry_private_history_required")
	}
	archive := filepath.Join(history, fmt.Sprintf("attempt-%d.json", old))
	saved, err := readRetryPrivate(archive)
	if err == nil {
		if !bytes.Equal(saved, raw) {
			return errors.New("retry_history_conflict")
		}
	} else if !os.IsNotExist(err) {
		return err
	} else {
		if current == old+1 {
			return errors.New("retry_history_missing")
		}
		file, createErr := os.CreateTemp(history, ".receipt-")
		if createErr != nil {
			return createErr
		}
		name := file.Name()
		defer os.Remove(name) //nolint:errcheck
		if _, err = file.Write(raw); err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if err = os.Link(name, archive); err != nil {
			return err
		}
	}
	// The controller writes its diagnostic with O_EXCL. Archive the previous
	// attempt's result and remove it before retry so a later failure cannot
	// inherit a stale task name in its receipt.
	diagnosticPath := filepath.Join(directory, "diagnostic.json")
	diagnostic, diagnosticErr := readRetryPrivate(diagnosticPath)
	if diagnosticErr != nil && !os.IsNotExist(diagnosticErr) {
		return diagnosticErr
	}
	if diagnosticErr == nil {
		diagnosticArchive := filepath.Join(history, fmt.Sprintf("diagnostic-attempt-%d.json", old))
		savedDiagnostic, archiveErr := readRetryPrivate(diagnosticArchive)
		if archiveErr == nil {
			if !bytes.Equal(savedDiagnostic, diagnostic) {
				return errors.New("retry_diagnostic_history_conflict")
			}
		} else if !os.IsNotExist(archiveErr) {
			return archiveErr
		} else {
			file, createErr := os.CreateTemp(history, ".diagnostic-")
			if createErr != nil {
				return createErr
			}
			name := file.Name()
			defer os.Remove(name) //nolint:errcheck
			if _, err = file.Write(diagnostic); err == nil {
				err = file.Sync()
			}
			closeErr := file.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			if err = os.Link(name, diagnosticArchive); err != nil {
				return err
			}
		}
	}
	if err = syncDir(history); err != nil {
		return err
	}
	if err = syncDir(directory); err != nil {
		return err
	}
	if current == old {
		job["attempt"] = old + 1
		next, marshalErr := json.Marshal(job)
		if marshalErr != nil {
			return marshalErr
		}
		file, createErr := os.CreateTemp(directory, ".job-")
		if createErr != nil {
			return createErr
		}
		name := file.Name()
		defer os.Remove(name) //nolint:errcheck
		if _, err = file.Write(next); err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if err = os.Rename(name, jobPath); err != nil {
			return err
		}
	}
	// Also sync a job rename completed before a previous fsync failure.
	if err = syncDir(directory); err != nil {
		return err
	}
	if diagnosticErr == nil {
		if err = os.Remove(diagnosticPath); err != nil {
			return err
		}
	}
	if err = os.Remove(receiptPath); err != nil {
		return err
	}
	return syncDir(directory)
}

// ResumeFrozenBootstrapRollback retries only the original fixed rollback stage.
// It is deliberately separate from the bootstrap compatibility CLI allowlist.
func ResumeFrozenBootstrapRollback(
	ctx context.Context,
	inventory, variables map[string]any,
	directory, python, executable string,
) (Receipt, error) {
	if _, ok := ctx.Value(operationLeaseKey{}).(*operationLease); !ok {
		return Receipt{}, errors.New("retry requires operation lease")
	}
	return runLocal(ctx, "rollback-adoption", inventory, variables, directory, python, executable, true, "")
}
