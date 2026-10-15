package main

import (
	"encoding/json"
	"fmt"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// The maintenance consumer reconstructs the candidate from private host journals.
// Only the frozen public request and exact domain attempt cross this boundary.
func upgradeAcceptedResumeContract(p *installplan.InstallPlan, inspection upgradeInspection, inventory, variables map[string]any, directory string, domain *upgradeDomainTransaction, generation int) (map[string]any, error) {
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
			d["backend_policy"] = map[string]any{"old": v["ultra_backend_old_domain"], "new": v["ultra_bot_domain"], "public": v["ultra_backend_old_public"], "old_port": v["ultra_backend_old_port"], "new_port": v["ultra_bot_port"]}
		}
		contract["domain"] = d
	}
	return contract, nil
}
