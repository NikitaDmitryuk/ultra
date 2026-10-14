package deployansible

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Only the internal retention operation permits collection of its successful
// executable bundle. Its durable frozen inputs and terminal receipt still make
// repeating that same operation idempotent. Caller holds the operation lease.
func collectedRetentionResult(operation, directory string, raw []byte, id string) (Receipt, bool, error) {
	if operation != "retain-artifacts" {
		return Receipt{}, false, nil
	}
	info, err := os.Lstat(directory)
	if os.IsNotExist(err) {
		return Receipt{}, false, nil
	}
	if err != nil {
		return Receipt{}, true, err
	}
	if !info.IsDir() || !ownedByProcess(info) || info.Mode().Perm()&0077 != 0 {
		return Receipt{}, true, errors.New("retention_cached_directory_invalid")
	}
	if _, err = os.Lstat(filepath.Join(directory, "bundle")); err == nil {
		return Receipt{}, false, nil
	}
	if !os.IsNotExist(err) {
		return Receipt{}, true, err
	}
	if err = retentionNoSymlinkAncestors(directory); err != nil {
		return Receipt{}, true, err
	}
	request, err := readRetryPrivate(filepath.Join(directory, "request.json"))
	if err != nil || !bytes.Equal(request, raw) {
		return Receipt{}, true, errors.New("retention_cached_request_invalid")
	}
	digest := sha256.Sum256(request)
	if hex.EncodeToString(digest[:]) != id {
		return Receipt{}, true, errors.New("retention_cached_request_hash_invalid")
	}
	jobRaw, err := readRetryPrivate(filepath.Join(directory, "job.json"))
	if err != nil {
		return Receipt{}, true, errors.New("retention_cached_job_unavailable")
	}
	receiptRaw, err := readRetryPrivate(filepath.Join(directory, "receipt.json"))
	if err != nil {
		return Receipt{}, true, errors.New("retention_cached_receipt_unavailable")
	}
	var job, saved map[string]any
	var receipt Receipt
	if json.Unmarshal(jobRaw, &job) != nil || json.Unmarshal(receiptRaw, &saved) != nil || json.Unmarshal(receiptRaw, &receipt) != nil {
		return Receipt{}, true, errors.New("retention_cached_metadata_invalid")
	}
	for _, value := range []map[string]any{job, saved} {
		if value["schema_version"] != float64(1) || value["operation"] != operation || value["request_sha256"] != id || value["binary_sha256"] != id {
			return Receipt{}, true, errors.New("retention_cached_identity_invalid")
		}
	}
	jobAttempt, err := retryAttempt(job["attempt"])
	if err != nil {
		return Receipt{}, true, err
	}
	savedAttempt, err := retryAttempt(saved["attempt"])
	if err != nil || savedAttempt != jobAttempt {
		return Receipt{}, true, errors.New("retention_cached_attempt_invalid")
	}
	if receipt.State != "succeeded" || receipt.Result.Values["verified"] != true {
		return Receipt{}, true, errors.New("retention_cached_success_required")
	}
	return receipt, true, nil
}
