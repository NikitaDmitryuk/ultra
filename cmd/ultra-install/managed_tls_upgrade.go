package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// Generation-bound inputs are public. Certificate and account contents never
// enter the controller request, variables, receipts, or operator journal.
func attachManagedTunnelVariables(
	p *installplan.InstallPlan,
	requests map[string]any,
	variables, releaseVariables map[string]any,
	directory string,
	generation int,
) error {
	if p.Features.MainExitDomain == "" {
		return nil
	}
	if len(p.Exits) != 1 || len(requests) != 2 || generation < 1 || releaseVariables["ultra_release_manifest"] == nil {
		return errors.New("upgrade_managed_tunnel_identity_unverified")
	}
	hookSHA, err := managedTunnelHookSHA(p.Features.MainExitDomain)
	if err != nil {
		return err
	}
	fences := map[string]string{}
	for host, raw := range requests {
		in, ok := raw.(runtimeProbeInput)
		if !ok {
			return errors.New("upgrade_managed_tunnel_identity_unverified")
		}
		if in.Request.Role != config.RoleExit {
			continue
		}
		in.Request.Transaction = fmt.Sprintf("%s-runtime-%d", lifecycleID(directory), generation)
		request := struct {
			Transaction       string `json:"transaction"`
			Domain            string `json:"domain"`
			RuntimeRequestSHA string `json:"runtime_request_sha256"`
			ReleaseSHA        string `json:"release_sha256"`
		}{in.Request.Transaction, p.Features.MainExitDomain, runtimeHostDigest(in.Request), runtimeHostDigest(releaseVariables["ultra_release_manifest"])}
		encoded, marshalErr := json.Marshal(request)
		if marshalErr != nil {
			return marshalErr
		}
		fences[host] = string(encoded)
	}
	if len(fences) != 1 {
		return errors.New("upgrade_managed_tunnel_identity_unverified")
	}
	variables["ultra_managed_tunnel_requests"] = fences
	variables["ultra_managed_tunnel_hook_sha256"] = hookSHA
	return nil
}

// Call only after the compatible binary rollback and all fleet payload checks
// succeeded. Runtime rollback alone must retain the certificate/renewal fence.
func releaseManagedUpgradeTunnel(ctx context.Context, p *installplan.InstallPlan, inspection upgradeInspection,
	inventory, releaseVariables map[string]any, directory, python, executable string, generation int) error {
	if p.Features.MainExitDomain == "" {
		return nil
	}
	requests, err := upgradeRuntimeRequests(p, inspection, inventory, fmt.Sprintf("%s-runtime-%d", lifecycleID(directory), generation))
	if err != nil {
		return err
	}
	variables := map[string]any{
		"ultra_runtime_action":         "tls-release",
		"ultra_lock_directory":         releaseVariables["ultra_lock_directory"],
		"ultra_runtime_probe_requests": requests,
	}
	if err = attachManagedTunnelVariables(p, requests, variables, releaseVariables, directory, generation); err != nil {
		return err
	}
	receipt, err := deployansible.RunLocalRetryFailed(ctx, "upgrade-runtime", inventory, variables,
		upgradeDependentStageDirectory(directory, "managed-tls-release", generation), python, executable)
	if err != nil {
		return err
	}
	if receipt.Result.Values["verified"] != true || receipt.Result.Values["phase"] != "tls-release" {
		return errors.New("upgrade_managed_tunnel_rollback_release_unverified")
	}
	return nil
}
