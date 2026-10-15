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
	case "bootstrap",
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
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
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

// Caller holds the matching infrastructure lease. Archive, advance, and remove
// are deliberately ordered: every interruption retains a recoverable failure.
func retryFailedLocalAttempt(directory string) error {
	return retryFailedLocalAttemptWith(directory, syncDirectory)
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
