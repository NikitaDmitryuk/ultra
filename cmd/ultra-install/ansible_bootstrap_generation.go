package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type bootstrapRollbackProof struct {
	Schema       int    `json:"schema"`
	ID           string `json:"id"`
	Generation   int    `json:"generation"`
	InventorySHA string `json:"inventory_sha256"`
	ReceiptSHA   string `json:"rollback_receipt_sha256"`
}

func bootstrapMutationStage(directory, stage string, generation int) string {
	if generation == 1 {
		return filepath.Join(directory, stage)
	}
	return filepath.Join(directory, fmt.Sprintf("%s-generation-%d", stage, generation))
}

func readBootstrapGenerationInput(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 {
		return nil, errors.New("bootstrap_generation_input_invalid")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("bootstrap_generation_input_invalid")
	}
	return os.ReadFile(path)
}

// The operation lease is held by the transaction caller. A generation advances
// only after a matching compatible rollback receipt proves its effects undone.
// Missing proof after a crash is reconstructed from that same durable receipt.
func bootstrapMutationGeneration(directory string, inventory map[string]any) (int, error) {
	for generation := 1; generation <= 100; generation++ {
		advanced, err := recordBootstrapRollbackProof(directory, inventory, generation)
		if err != nil {
			return 0, err
		}
		if !advanced {
			return generation, nil
		}
	}
	return 0, errors.New("bootstrap_generation_limit")
}

func recordBootstrapRollbackProof(directory string, inventory map[string]any, generation int) (bool, error) {
	stage := bootstrapMutationStage(directory, "rollback-adoption", generation)
	marker := filepath.Join(directory, fmt.Sprintf("rollback-generation-%d.json", generation))
	if info, stageErr := os.Lstat(stage); stageErr == nil {
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !info.IsDir() || info.Mode().Perm()&0077 != 0 || !ok || owner.Uid != uint32(os.Geteuid()) {
			return false, errors.New("bootstrap_generation_input_invalid")
		}
	} else if !os.IsNotExist(stageErr) {
		return false, stageErr
	}
	receipt, err := readBootstrapGenerationInput(filepath.Join(stage, "receipt.json"))
	if os.IsNotExist(err) {
		if generation == 1 {
			entries, readErr := os.ReadDir(directory)
			if readErr != nil {
				return false, readErr
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), "rollback-adoption-") && !strings.HasPrefix(entry.Name(), "rollback-adoption-generation-") {
					return false, errors.New("bootstrap_legacy_rollback_proof_required")
				}
			}
		}
		if _, markerErr := os.Lstat(marker); !os.IsNotExist(markerErr) {
			return false, errors.New("bootstrap_rollback_proof_missing_receipt")
		}
		if _, jobErr := os.Lstat(filepath.Join(stage, "job.json")); !os.IsNotExist(jobErr) {
			return false, errors.New("bootstrap_compatible_rollback_unconfirmed")
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var saved, job map[string]any
	jobRaw, err := readBootstrapGenerationInput(filepath.Join(stage, "job.json"))
	if err != nil {
		return false, err
	}
	request, err := readBootstrapGenerationInput(filepath.Join(stage, "request.json"))
	if err != nil {
		return false, err
	}
	expected, err := json.Marshal(map[string]any{"inventory": inventory, "variables": map[string]any{"ultra_lifecycle_id": lifecycleID(directory)}})
	if err != nil {
		return false, err
	}
	requestHash := sha256.Sum256(request)
	if !bytes.Equal(expected, request) || json.Unmarshal(receipt, &saved) != nil || json.Unmarshal(jobRaw, &job) != nil || job["operation"] != "rollback-adoption" || saved["operation"] != job["operation"] || job["request_sha256"] != hex.EncodeToString(requestHash[:]) || saved["request_sha256"] != job["request_sha256"] || saved["binary_sha256"] != job["binary_sha256"] || saved["state"] != "succeeded" || job["binary_sha256"] != job["request_sha256"] || job["schema_version"] != float64(1) || saved["schema_version"] != job["schema_version"] || saved["attempt"] != job["attempt"] {
		return false, errors.New("bootstrap_compatible_rollback_unconfirmed")
	}
	values, ok := saved["result"].(map[string]any)
	if !ok || values["verified"] != true {
		return false, errors.New("bootstrap_compatible_rollback_unconfirmed")
	}
	inventoryRaw, err := json.Marshal(inventory)
	if err != nil {
		return false, err
	}
	inventoryHash := sha256.Sum256(inventoryRaw)
	receiptHash := sha256.Sum256(receipt)
	proof := bootstrapRollbackProof{Schema: 1, ID: lifecycleID(directory), Generation: generation, InventorySHA: hex.EncodeToString(inventoryHash[:]), ReceiptSHA: hex.EncodeToString(receiptHash[:])}
	raw, err := json.Marshal(proof)
	if err != nil {
		return false, err
	}
	if err = writeUpgradeInput(marker, raw); err != nil {
		return false, err
	}
	if err = syncUpgradeDirectory(directory); err != nil {
		return false, err
	}
	return true, nil
}

func bootstrapMutationSource(directory, stage string) (string, error) {
	source := filepath.Join(directory, stage)
	if _, err := os.Lstat(filepath.Join(source, "job.json")); os.IsNotExist(err) {
		anchor := filepath.Join(directory, "bootstrap-postgres")
		if _, anchorErr := os.Lstat(filepath.Join(anchor, "job.json")); anchorErr == nil {
			return anchor, nil
		} else if !os.IsNotExist(anchorErr) {
			return "", anchorErr
		}
		return filepath.Join(directory, "apply"), nil
	} else if err != nil {
		return "", err
	}
	return source, nil
}

func runBootstrapMutationStage(ctx context.Context, operation string, inventory, variables map[string]any, directory, stage string, generation int, python, executable string) (deployansible.Receipt, error) {
	target := bootstrapMutationStage(directory, stage, generation)
	source, err := bootstrapMutationSource(directory, stage)
	if err != nil {
		return deployansible.Receipt{}, err
	}
	if target == source {
		return deployansible.RunLocalRetryFailed(ctx, operation, inventory, variables, target, python, executable)
	}
	return deployansible.RunLocalRetryFailedPinned(ctx, operation, inventory, variables, target, source, python, executable)
}

func bootstrapMutationOriginalStage(directory, stage string, generation int) string {
	source, err := bootstrapMutationSource(directory, stage)
	if err != nil {
		return filepath.Join(directory, stage)
	}
	if generation == 1 && source == filepath.Join(directory, stage) {
		return ""
	}
	return source
}

// Only the whole operator transaction can finish a pending rollback. This runs
// before re-reserving stopped applications and before any new base mutation.
func resumeBootstrapMutationGeneration(ctx context.Context, p *installplan.InstallPlan, directory string, inventory map[string]any, python, executable string) (int, error) {
	for generation := 1; generation <= 100; generation++ {
		advanced, err := recordBootstrapRollbackProof(directory, inventory, generation)
		if err == nil {
			if advanced {
				continue
			}
			return generation, nil
		}
		marker := filepath.Join(directory, fmt.Sprintf("rollback-generation-%d.json", generation))
		if _, markerErr := os.Lstat(marker); !os.IsNotExist(markerErr) {
			return 0, err
		}
		stage := bootstrapMutationStage(directory, "rollback-adoption", generation)
		jobRaw, jobErr := readBootstrapGenerationInput(filepath.Join(stage, "job.json"))
		if jobErr != nil {
			return 0, err
		}
		request, requestErr := readBootstrapGenerationInput(filepath.Join(stage, "request.json"))
		expected, marshalErr := json.Marshal(map[string]any{"inventory": inventory, "variables": map[string]any{"ultra_lifecycle_id": lifecycleID(directory)}})
		var job map[string]any
		digest := sha256.Sum256(request)
		if requestErr != nil || marshalErr != nil || !bytes.Equal(request, expected) || json.Unmarshal(jobRaw, &job) != nil || job["operation"] != "rollback-adoption" || job["schema_version"] != float64(1) || job["request_sha256"] != hex.EncodeToString(digest[:]) || job["binary_sha256"] != job["request_sha256"] {
			return 0, errors.New("bootstrap_rollback_resume_inputs_invalid")
		}
		if receipt, receiptErr := readBootstrapGenerationInput(filepath.Join(stage, "receipt.json")); receiptErr == nil {
			var saved map[string]any
			if json.Unmarshal(receipt, &saved) != nil || saved["operation"] != job["operation"] || saved["schema_version"] != job["schema_version"] || saved["request_sha256"] != job["request_sha256"] || saved["binary_sha256"] != job["binary_sha256"] || (saved["state"] != "running" && saved["state"] != "failed") {
				return 0, errors.New("bootstrap_rollback_resume_receipt_invalid")
			}
		} else if !os.IsNotExist(receiptErr) {
			return 0, receiptErr
		}
		if err = ansibleResumeFrozenLifecycle(ctx, p, inventory, directory, python, executable); err != nil {
			return 0, err
		}
		if _, err = deployansible.ResumeFrozenBootstrapRollback(ctx, inventory, map[string]any{"ultra_lifecycle_id": lifecycleID(directory)}, stage, python, executable); err != nil {
			return 0, err
		}
		if _, err = recordBootstrapRollbackProof(directory, inventory, generation); err != nil {
			return 0, err
		}
	}
	return 0, errors.New("bootstrap_generation_limit")
}
