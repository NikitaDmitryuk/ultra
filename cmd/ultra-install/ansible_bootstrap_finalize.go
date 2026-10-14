package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

type bootstrapFinalization struct {
	Schema       int    `json:"schema_version"`
	ID           string `json:"operation_id"`
	InventorySHA string `json:"inventory_sha256"`
	Phase        string `json:"phase"`
}

func bootstrapFinalizationInputs(directory string) (map[string]any, string, error) {
	path := filepath.Join(directory, "inventory.frozen.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 {
		return nil, "", errors.New("bootstrap_finalization_inventory_invalid")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, "", errors.New("bootstrap_finalization_inventory_invalid")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	var inventory map[string]any
	if json.Unmarshal(raw, &inventory) != nil || inventory == nil {
		return nil, "", errors.New("bootstrap_finalization_inventory_invalid")
	}
	digest := sha256.Sum256(raw)
	return inventory, hex.EncodeToString(digest[:]), nil
}

func markBootstrapVerified(directory string) error {
	_, digest, err := bootstrapFinalizationInputs(directory)
	if err != nil {
		return err
	}
	return saveBootstrapAttempt(filepath.Join(directory, "finalization.json"), bootstrapFinalization{Schema: 1, ID: lifecycleID(directory), InventorySHA: digest, Phase: "verified"})
}

// Finalization is separate from application rollback. A lost gate-release reply
// or failed local journal write must never revert an already verified fleet.
func resumeBootstrapFinalization(ctx context.Context, p *installplan.InstallPlan, directory, planRoot, python, executable string) (bool, error) {
	if cached, err := completedOperatorOperation(directory, "bootstrap", ""); cached {
		if err != nil {
			return true, err
		}
		if p.Automation == nil {
			return true, errors.New("operator_retention_completed_plan_changed")
		}
		if err = matchOperatorPlan(directory, p, p.Automation.ReleaseDir); err != nil {
			return true, err
		}
		return true, completeBootstrapAttempt(planRoot, directory)
	}
	path := filepath.Join(directory, "finalization.json")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
		return true, errors.New("bootstrap_finalization_invalid")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return true, errors.New("bootstrap_finalization_invalid")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return true, err
	}
	var state bootstrapFinalization
	if json.Unmarshal(raw, &state) != nil || state.Schema != 1 || state.ID != lifecycleID(directory) || (state.Phase != "verified" && state.Phase != "released") {
		return true, errors.New("bootstrap_finalization_invalid")
	}
	inventory, digest, err := bootstrapFinalizationInputs(directory)
	if err != nil {
		return true, err
	}
	if digest != state.InventorySHA {
		return true, errors.New("bootstrap_finalization_inventory_changed")
	}
	if state.Phase == "verified" {
		if err = ansibleLifecycle(ctx, p, inventory, directory, python, executable, "released", false); err != nil {
			return true, err
		}
		state.Phase = "released"
		if err = saveBootstrapAttempt(path, state); err != nil {
			return true, err
		}
	}
	// Non-automation legacy flows have no verified release identity and are not
	// eligible for collection; their original continuation contract is preserved.
	if p.Automation == nil {
		return true, completeBootstrapAttempt(planRoot, directory)
	}
	manifest, err := verifyAutomationRelease(p.Automation.ReleaseDir, p.Automation.Version)
	if err != nil {
		return true, err
	}
	manifestSHA, err := sourceSHA(filepath.Join(p.Automation.ReleaseDir, "release-manifest.json"))
	if err != nil {
		return true, err
	}
	if err = sealCompletedOperatorOperation(directory, "bootstrap", manifest, manifestSHA); err != nil {
		return true, err
	}
	if err = completeBootstrapAttempt(planRoot, directory); err != nil {
		return true, err
	}
	return true, collectCompletedOperatorArtifacts(filepath.Dir(planRoot), manifest)
}
