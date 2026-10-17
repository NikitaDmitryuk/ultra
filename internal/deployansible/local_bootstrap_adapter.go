package deployansible

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	ansibleassets "github.com/NikitaDmitryuk/ultra/deploy/ansible"
)

// RunLocalRetryFailedAdaptedBootstrapPostgres creates a linked component anchor
// from an old bootstrap job. Original roles and all other infrastructure source
// bytes stay intact; only the supervisor and three fixed component plays change.
// This operator-only API has no caller-selected operation or overlay paths.
func RunLocalRetryFailedAdaptedBootstrapPostgres(
	ctx context.Context,
	inventory, variables map[string]any,
	directory, source, python, executable string,
) (Receipt, error) {
	lease, ok := ctx.Value(operationLeaseKey{}).(*operationLease)
	if !ok {
		return Receipt{}, errors.New("retry requires operation lease")
	}
	lease.run.Lock()
	err := prepareAdaptedBootstrapPostgres(lease, inventory, variables, directory, source)
	lease.run.Unlock()
	if err != nil {
		return Receipt{}, err
	}
	return RunLocalRetryFailed(ctx, "bootstrap-postgres", inventory, variables, directory, python, executable)
}

func prepareAdaptedBootstrapPostgres(lease *operationLease, inventory, variables map[string]any, directory, source string) error {
	if !lease.active.Load() || variables["ultra_lock_directory"] != lease.directory {
		return errors.New("operation lease directory mismatch")
	}
	return verifyOrPrepareAdaptedBootstrapPostgres(inventory, variables, directory, source, true)
}

// VerifyAdaptedBootstrapPostgres authenticates the complete fixed overlay tree without preparing or executing a job.
func VerifyAdaptedBootstrapPostgres(inventory, variables map[string]any, directory, source string) error {
	return verifyOrPrepareAdaptedBootstrapPostgres(inventory, variables, directory, source, false)
}

func verifyOrPrepareAdaptedBootstrapPostgres(inventory, variables map[string]any, directory, source string, prepare bool) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return errors.New("bootstrap_adapter_directory_invalid")
	}
	request, err := json.Marshal(map[string]any{"inventory": inventory, "variables": variables})
	if err != nil {
		return err
	}
	original, err := readRetryPrivate(filepath.Join(source, "request.json"))
	if err != nil {
		return err
	}
	jobRaw, err := readRetryPrivate(filepath.Join(source, "job.json"))
	if err != nil {
		return err
	}
	var job map[string]any
	var frozen struct {
		Inventory map[string]any `json:"inventory"`
		Variables map[string]any `json:"variables"`
	}
	if json.Unmarshal(jobRaw, &job) != nil || job["operation"] != "bootstrap" || json.Unmarshal(original, &frozen) != nil {
		return errors.New("bootstrap_adapter_original_required")
	}
	frozenRaw, _ := json.Marshal(frozen.Inventory)
	nextRaw, _ := json.Marshal(inventory)
	if frozen.Inventory == nil || !bytes.Equal(frozenRaw, nextRaw) ||
		frozen.Variables["ultra_lock_directory"] != variables["ultra_lock_directory"] {
		return errors.New("bootstrap_adapter_frozen_inventory_changed")
	}
	baseExport, err := pinnedBootstrapExporter(source, directory, "bootstrap-postgres", request)
	if err != nil {
		return err
	}
	base, err := retentionInventory(filepath.Join(source, "bundle"))
	if err != nil {
		return err
	}
	baseRaw, _ := json.Marshal(base)
	baseHash := sha256.Sum256(baseRaw)
	overlay := map[string][]byte{}
	overlayHashes := map[string]string{}
	for _, name := range []string{"controller.py", "playbooks/bootstrap-postgres.yml", "playbooks/bootstrap-exit.yml", "playbooks/bootstrap-bridge.yml"} {
		data, readErr := ansibleassets.Bundle.ReadFile(name)
		if readErr != nil {
			return readErr
		}
		overlay[name] = data
		hash := sha256.Sum256(data)
		overlayHashes[name] = hex.EncodeToString(hash[:])
		base[name] = []any{"file", hex.EncodeToString(hash[:]), uint32(0600)}
	}
	overlayRaw, _ := json.Marshal(overlayHashes)
	overlayHash := sha256.Sum256(overlayRaw)
	proof, _ := json.Marshal(
		map[string]any{
			"schema":                1,
			"parent_source":         source,
			"parent_request_sha256": job["request_sha256"],
			"parent_bundle_sha256":  hex.EncodeToString(baseHash[:]),
			"adapter_sha256":        hex.EncodeToString(overlayHash[:]),
		},
	)
	if _, statErr := os.Lstat(directory); statErr == nil {
		saved, readErr := readRetryPrivate(filepath.Join(directory, "bundle.adapter.json"))
		if readErr != nil || !bytes.Equal(saved, proof) {
			return errors.New("bootstrap_adapter_proof_conflict")
		}
	} else if !os.IsNotExist(statErr) {
		return statErr
	}
	digest := sha256.Sum256(request)
	export := func(target string) error {
		if err := baseExport(target); err != nil {
			return err
		}
		for name, data := range overlay {
			path := filepath.Join(target, filepath.FromSlash(name))
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
			if err := writePrivate(filepath.Join(target, filepath.FromSlash(name)), data); err != nil {
				return err
			}
		}
		return writePrivate(filepath.Join(filepath.Dir(target), "bundle.adapter.json"), proof)
	}
	if prepare {
		if err := prepareLocalOperation(directory, "bootstrap-postgres", request, hex.EncodeToString(digest[:]), export); err != nil {
			return err
		}
	} else {
		saved, err := readRetryPrivate(filepath.Join(directory, "request.json"))
		if err != nil || !bytes.Equal(saved, request) {
			return errors.New("bootstrap_adapter_request_changed")
		}
	}
	actual, err := retentionInventory(filepath.Join(directory, "bundle"))
	if err != nil {
		return err
	}
	expectedRaw, _ := json.Marshal(base)
	actualRaw, _ := json.Marshal(actual)
	if !bytes.Equal(expectedRaw, actualRaw) {
		return errors.New("bootstrap_adapter_bundle_changed")
	}
	return nil
}
