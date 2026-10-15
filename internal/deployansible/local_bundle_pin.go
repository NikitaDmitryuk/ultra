package deployansible

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// RunLocalRetryFailedPinned is an operator-only bootstrap generation adapter.
// The original private stage is the only source; no relay/service API exposes it.
func RunLocalRetryFailedPinned(ctx context.Context, operation string, inventory, variables map[string]any, directory, source, python, executable string) (Receipt, error) {
	if !bootstrapRetryOperation(operation) || operation == "reserve-rolledback-bootstrap" {
		return Receipt{}, errors.New("retry_bootstrap_operation_required")
	}
	if _, ok := ctx.Value(operationLeaseKey{}).(*operationLease); !ok {
		return Receipt{}, errors.New("retry requires operation lease")
	}
	return runLocal(ctx, operation, inventory, variables, directory, python, executable, true, source)
}

func pinnedBootstrapExporter(source, directory, operation string, request []byte) (func(string) error, error) {
	if !filepath.IsAbs(source) || filepath.Clean(source) != source || source == directory {
		return nil, errors.New("bootstrap_bundle_source_invalid")
	}
	if err := retentionNoSymlinkAncestors(source); err != nil {
		return nil, err
	}
	info, err := os.Lstat(source)
	if err != nil || !info.IsDir() || !ownedByProcess(info) || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("bootstrap_bundle_source_invalid")
	}
	jobRaw, err := readRetryPrivate(filepath.Join(source, "job.json"))
	if err != nil {
		return nil, err
	}
	oldRequest, err := readRetryPrivate(filepath.Join(source, "request.json"))
	if err != nil {
		return nil, err
	}
	var job map[string]any
	hash := sha256.Sum256(oldRequest)
	if json.Unmarshal(jobRaw, &job) != nil || job["schema_version"] != float64(1) || job["request_sha256"] != hex.EncodeToString(hash[:]) || job["binary_sha256"] != job["request_sha256"] || (job["operation"] != operation && job["operation"] != "bootstrap" && job["operation"] != "bootstrap-postgres") {
		return nil, errors.New("bootstrap_bundle_source_identity_invalid")
	}
	if job["operation"] == "bootstrap-postgres" {
		switch operation {
		case "bootstrap-postgres", "bootstrap-exit", "bootstrap-bridge", "ingress", "configure-bot", "bootstrap-automation":
		default:
			return nil, errors.New("bootstrap_component_bundle_destination_invalid")
		}
		var original, next struct {
			Inventory map[string]any `json:"inventory"`
		}
		if json.Unmarshal(oldRequest, &original) != nil || json.Unmarshal(request, &next) != nil || original.Inventory == nil || next.Inventory == nil {
			return nil, errors.New("bootstrap_component_inventory_invalid")
		}
		a, _ := json.Marshal(original.Inventory)
		b, _ := json.Marshal(next.Inventory)
		if !bytes.Equal(a, b) {
			return nil, errors.New("bootstrap_component_inventory_changed")
		}
	}
	if job["operation"] == operation && !bytes.Equal(oldRequest, request) {
		return nil, errors.New("bootstrap_original_stage_inputs_changed")
	}
	sourceBundle := filepath.Join(source, "bundle")
	if err = retentionNoSymlinkAncestors(sourceBundle); err != nil {
		return nil, err
	}
	inventory, err := retentionInventory(sourceBundle)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(inventory)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	pin, _ := json.Marshal(map[string]any{"schema": 1, "source": source, "operation": operation, "source_request_sha256": job["request_sha256"], "bundle_sha256": hex.EncodeToString(digest[:])})
	if _, err = os.Lstat(directory); err == nil {
		existing, readErr := readRetryPrivate(filepath.Join(directory, "bundle.source.json"))
		if readErr != nil || !bytes.Equal(existing, pin) {
			return nil, errors.New("bootstrap_bundle_pin_conflict")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return func(target string) error {
		if err := filepath.WalkDir(sourceBundle, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			relative, err := filepath.Rel(sourceBundle, path)
			if err != nil {
				return err
			}
			destination := filepath.Join(target, relative)
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return os.MkdirAll(destination, info.Mode().Perm())
			}
			data, err := readPinnedBundleFile(path)
			if err != nil {
				return err
			}
			if err = writePrivate(destination, data); err != nil {
				return err
			}
			return os.Chmod(destination, info.Mode().Perm())
		}); err != nil {
			return err
		}
		copied, err := retentionInventory(target)
		if err != nil {
			return err
		}
		copiedRaw, err := json.Marshal(copied)
		if err != nil {
			return err
		}
		after, err := retentionInventory(sourceBundle)
		if err != nil {
			return err
		}
		afterRaw, err := json.Marshal(after)
		if err != nil {
			return err
		}
		if !bytes.Equal(raw, copiedRaw) || !bytes.Equal(raw, afterRaw) {
			return errors.New("bootstrap_bundle_changed_during_copy")
		}
		return writePrivate(filepath.Join(filepath.Dir(target), "bundle.source.json"), pin)
	}, nil
}

func readPinnedBundleFile(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close() //nolint:errcheck
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !ownedByProcess(info) || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 {
		return nil, errors.New("bootstrap_bundle_file_invalid")
	}
	return io.ReadAll(io.LimitReader(file, 1<<20+1))
}
