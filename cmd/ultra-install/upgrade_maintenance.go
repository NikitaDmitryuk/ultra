package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// The lease and owned remote gate must still be held. A checkpoint is written
// before any producer stop or release/runtime activation. Never infer this
// decision from a failed local receipt: inspect the exact live legacy process.
func untouchedLegacyUpgrade(
	ctx context.Context,
	legacy bool,
	p *installplan.InstallPlan,
	inspection upgradeInspection,
	inventory, variables map[string]any,
	directory, python, executable string,
	generation int,
) (bool, error) {
	if !legacy {
		return false, nil
	}
	inspectionDirectory, err := os.MkdirTemp(directory, "maintenance-inspect-")
	if err != nil {
		return false, err
	}
	if err = os.Remove(inspectionDirectory); err != nil {
		return false, err
	}
	requests, err := upgradeRuntimeRequests(p, inspection, inventory, fmt.Sprintf("%s-runtime-%d", lifecycleID(directory), generation))
	if err != nil {
		return false, err
	}
	authorizeUpgradeDomainRequest(requests, variables)
	raw, err := json.Marshal(requests["bridge"])
	if err != nil {
		return false, err
	}
	inspectVariables := map[string]any{}
	for key, value := range variables {
		inspectVariables[key] = value
	}
	inspectVariables["ultra_legacy_initial_runtime_request_json"] = string(raw)
	receipt, err := deployansible.RunLocal(
		ctx,
		"inspect-upgrade-maintenance",
		inventory,
		inspectVariables,
		inspectionDirectory,
		python,
		executable,
	)
	if err != nil {
		return false, err
	}
	untouched, ok := receipt.Result.Values["untouched"].(bool)
	if receipt.Result.Values["verified"] != true || !ok {
		return false, errors.New("upgrade_legacy_compensation_unverified")
	}
	return untouched, nil
}
