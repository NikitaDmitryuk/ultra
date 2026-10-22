package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// The maintenance consumer reconstructs the candidate from private host journals.
// Only the frozen public request and exact domain attempt cross this boundary.
func upgradeAcceptedResumeContract(
	p *installplan.InstallPlan,
	inspection upgradeInspection,
	inventory, variables map[string]any,
	directory string,
	domain *upgradeDomainTransaction,
	generation int,
) (map[string]any, error) {
	requests, err := upgradeRuntimeRequests(p, inspection, inventory, fmt.Sprintf("%s-runtime-%d", lifecycleID(directory), generation))
	if err != nil {
		return nil, err
	}
	authorizeUpgradeDomainRequest(requests, variables)
	raw, err := json.Marshal(requests["bridge"])
	if err != nil {
		return nil, err
	}
	contract := map[string]any{"generation": generation, "runtime_request_json": string(raw)}
	if domain != nil && domain.Changed {
		if err := domain.loadAttempt(directory, generation); err != nil {
			return nil, err
		}
		v := domain.Variables
		d := map[string]any{"binding": domain.Binding, "attempt": domain.Attempt, "plan": v["ultra_ingress"]}
		if domain.BackendChanged {
			d["backend_policy"] = map[string]any{
				"old":      v["ultra_backend_old_domain"],
				"new":      v["ultra_bot_domain"],
				"public":   v["ultra_backend_old_public"],
				"old_port": v["ultra_backend_old_port"],
				"new_port": v["ultra_bot_port"],
			}
		}
		contract["domain"] = d
	}
	return contract, nil
}

// A committed retry must resume the already accepted candidate configuration.
// Keep that exact contract separate from retry-preflight's additional fields.
func upgradeRetryResumeContracts(contract map[string]any, committed bool) (map[string]any, map[string]any) {
	retry := make(map[string]any)
	for key, value := range contract {
		retry[key] = value
	}
	retry["mode"] = "compensation"
	if !committed {
		return retry, nil
	}
	accepted := make(map[string]any)
	for key, value := range contract {
		accepted[key] = value
	}
	retry["mode"] = "committed"
	return retry, accepted
}

func upgradeResumeVariables(lock, operation string, legacy bool, legacySHA string, accepted map[string]any) map[string]any {
	variables := map[string]any{"ultra_lock_directory": lock}
	if legacy {
		variables["ultra_legacy_bridge_maintenance"] = true
		variables["ultra_legacy_bridge_sha256"] = legacySHA
		variables["ultra_lifecycle_id"] = operation
		if accepted != nil {
			variables["ultra_legacy_accepted_resume"] = accepted
		}
	}
	return variables
}

// Only an already committed continuation may reuse this exact successful
// cleanup. Ordinary failed/rolled-back attempts must restore schedules anew.
func successfulUpgradeResume(directory string, inventory, variables map[string]any) (bool, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "resume-") {
			continue
		}
		stage := filepath.Join(directory, entry.Name())
		if operatorPrivate(stage, true) != nil {
			continue
		}
		jobRaw, jobErr := readBootstrapGenerationInput(filepath.Join(stage, "job.json"))
		requestRaw, requestErr := readBootstrapGenerationInput(filepath.Join(stage, "request.json"))
		receiptRaw, receiptErr := readBootstrapGenerationInput(filepath.Join(stage, "receipt.json"))
		expected, expectedErr := expectedFrozenLocalRequest(requestRaw, inventory, variables)
		expectedSHA := digestSHA256(expected)
		var job struct {
			Schema    int    `json:"schema_version"`
			Operation string `json:"operation"`
			Request   string `json:"request_sha256"`
			Binary    string `json:"binary_sha256"`
		}
		var receipt deployansible.Receipt
		if jobErr != nil || requestErr != nil || receiptErr != nil || expectedErr != nil || string(requestRaw) != string(expected) ||
			json.Unmarshal(jobRaw, &job) != nil || json.Unmarshal(receiptRaw, &receipt) != nil ||
			job.Schema != 1 || job.Operation != "resume-automation" || job.Request != expectedSHA || !runtimeHostValidDigest(job.Binary) ||
			receipt.RequestSHA256 != expectedSHA || receipt.BinarySHA256 != job.Binary || receipt.State != "succeeded" {
			continue
		}
		return true, nil
	}
	return false, nil
}
