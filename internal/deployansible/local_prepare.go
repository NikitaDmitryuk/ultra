package deployansible

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Preparation has no external effects. Publish the complete, synced workspace
// in one rename so an interrupted export never becomes a resumable operation.
// The caller holds the infrastructure lease throughout preparation and execution.
func prepareLocalOperation(directory, operation string, raw []byte, id string, export func(string) error) error {
	info, err := os.Lstat(directory)
	if err == nil {
		if !info.IsDir() || !ownedByProcess(info) || info.Mode().Perm()&0077 != 0 {
			return errors.New("private local operation directory required")
		}
		var job struct {
			Operation string `json:"operation"`
			Hash      string `json:"request_sha256"`
		}
		data, readErr := os.ReadFile(filepath.Join(directory, "job.json"))
		request, requestErr := os.ReadFile(filepath.Join(directory, "request.json"))
		if readErr != nil || requestErr != nil || json.Unmarshal(data, &job) != nil || job.Operation != operation || job.Hash != id || !bytes.Equal(request, raw) {
			return errors.New("local operation inputs changed")
		}
		// A rename may have completed immediately before a parent fsync error.
		// Retrying must durably publish that same directory before execution.
		return syncDirectory(filepath.Dir(directory))
	}
	if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(directory)
	staging, err := os.MkdirTemp(parent, ".prepare-local-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	if err = writePrivate(filepath.Join(staging, "request.json"), raw); err != nil {
		return err
	}
	if err = writeJSON(filepath.Join(staging, "job.json"), map[string]any{"schema_version": 1, "operation": operation, "request_sha256": id, "binary_sha256": id}); err != nil {
		return err
	}
	if err = export(filepath.Join(staging, "bundle")); err != nil {
		return err
	}
	if err = WriteRetentionReceipt(filepath.Join(staging, "bundle"), filepath.Join(directory, "bundle"), filepath.Join(staging, "bundle.retention.json"), map[string]string{"request_sha256": id}); err != nil {
		return err
	}
	if err = syncTree(staging); err != nil {
		return err
	}
	if err = os.Rename(staging, directory); err != nil {
		return err
	}
	return syncDirectory(parent)
}
