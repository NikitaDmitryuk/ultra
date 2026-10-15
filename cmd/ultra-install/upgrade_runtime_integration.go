package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	ansibleassets "github.com/NikitaDmitryuk/ultra/deploy/ansible"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

type upgradeRuntimeNodeEvidence struct {
	Name                 string `json:"name"`
	Managed              bool   `json:"managed"`
	TunnelIdentityDigest string `json:"tunnel_identity_digest"`
	CertificatePin       string `json:"certificate_pin"`
}

func upgradeRuntimeRequests(
	p *installplan.InstallPlan,
	inspection upgradeInspection,
	inventory map[string]any,
	transaction string,
) (map[string]any, error) {
	if p == nil || p.SourceValues == nil {
		return nil, errors.New("upgrade_canonical_runtime_required")
	}
	r := runtimeHostRequest{
		Transaction: transaction,
		Role:        config.RoleBridge,
		Bridge:      p.Bridge,
		Database:    p.Database,
		Features:    p.Features,
		BotEnabled:  p.Bot.Enabled,
	}
	for _, ex := range p.Exits {
		r.Exits = append(r.Exits, runtimeHostExit{Name: ex.Name, SSHHost: ex.SSHHost, DialAddr: ex.DialAddr, Port: ex.Port})
	}
	in := runtimeProbeInput{Request: r, SubscriptionDomain: p.PublicSubscriptionDomain(), BotDomain: p.Bot.Domain}
	if p.Automation != nil && p.Automation.Ingress != nil {
		in.VPNDomain = p.Automation.Ingress.Domain
	}
	requests := map[string]any{"bridge": in}
	all, ok := inventory["all"].(map[string]any)
	if !ok {
		return nil, errors.New("upgrade_runtime_inventory_invalid")
	}
	children, ok := all["children"].(map[string]any)
	if !ok {
		return nil, errors.New("upgrade_runtime_inventory_invalid")
	}
	exits, ok := children["exits"].(map[string]any)
	if !ok {
		return nil, errors.New("upgrade_runtime_inventory_invalid")
	}
	hosts, ok := exits["hosts"].(map[string]any)
	if !ok || len(hosts) != len(inspection.Nodes) {
		return nil, errors.New("upgrade_runtime_inventory_invalid")
	}
	seen := map[string]bool{}
	for _, node := range inspection.Nodes {
		alias := "exit_" + strings.ReplaceAll(node.ID, "-", "")
		evidence, evidenceFound := inspection.RuntimeNodes[node.ID]
		if !evidenceFound {
			return nil, errors.New("upgrade_runtime_exit_proof_unavailable")
		}
		host, ok := hosts[alias].(map[string]any)
		if !ok || host["ansible_host"] != node.Address || host["ultra_exit_id"] != node.ID || host["ansible_user"] != "root" ||
			!runtimeHostValidDigest(evidence.TunnelIdentityDigest) ||
			(evidence.CertificatePin != "" && !runtimeHostValidDigest(evidence.CertificatePin)) {
			return nil, errors.New("upgrade_runtime_exit_proof_unavailable")
		}
		// Proofs are authorized only for the immutable strict SSH inventory built
		// from this bridge inspection, never a caller-provided name or address.
		sshArgs, ok := host["ansible_ssh_common_args"].(string)
		if !ok || !strings.Contains(sshArgs, "StrictHostKeyChecking=yes") || !strings.Contains(sshArgs, "IdentitiesOnly=yes") ||
			!strings.Contains(sshArgs, "UserKnownHostsFile=") ||
			node.Pins == "" {
			return nil, errors.New("upgrade_runtime_exit_proof_unavailable")
		}
		identityPath, ok := host["ansible_ssh_private_key_file"].(string)
		if !ok || !filepath.IsAbs(identityPath) || filepath.Base(identityPath) != "identity" ||
			host["ansible_ssh_args"] != "-F /dev/null -o ControlMaster=no -o ControlPath=none" {
			return nil, errors.New("upgrade_runtime_exit_proof_unavailable")
		}
		expectedArgs := "-o BatchMode=yes -o UpdateHostKeys=no -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -o UserKnownHostsFile=" + shellQuote(
			filepath.Join(filepath.Dir(identityPath), alias+".pins"),
		)
		if sshArgs != expectedArgs {
			return nil, errors.New("upgrade_runtime_exit_proof_unavailable")
		}
		name := ""
		for _, ex := range p.Exits {
			if ex.Name == evidence.Name && ex.SSHHost == node.Address && ex.DialAddr == node.Address {
				name = ex.Name
				break
			}
		}
		if (name == "" && !evidence.Managed) || (name != "" && seen[name]) {
			return nil, errors.New("upgrade_runtime_topology_migration_required")
		}
		if name != "" {
			seen[name] = true
		}
		exitRequest := r
		exitRequest.Role, exitRequest.Node = config.RoleExit, name
		exitRequest.Proof = &runtimeHostExitProof{
			Node:                 name,
			SSHHost:              node.Address,
			TunnelIdentityDigest: evidence.TunnelIdentityDigest,
			CertificatePin:       evidence.CertificatePin,
		}
		if name == "" {
			exitRequest.Proof.NodeID, exitRequest.Proof.TopologySHA = node.ID, inspection.TopologySHA
		}
		identity, err := runtimeHostDesiredIdentity(exitRequest)
		if err != nil {
			return nil, errors.New("upgrade_runtime_exit_proof_unavailable")
		}
		exitRequest.Proof.DesiredIdentity = identity
		requests[alias] = runtimeProbeInput{Request: exitRequest}
	}
	if len(seen) != len(p.Exits) {
		return nil, errors.New("upgrade_runtime_topology_migration_required")
	}
	return requests, nil
}

func runUpgradeRuntimePhase(
	ctx context.Context,
	p *installplan.InstallPlan,
	inspection upgradeInspection,
	inventory, releaseVariables map[string]any,
	directory, python, executable, action string,
	generation int,
	retryFailed ...bool,
) error {
	if action != "prepare" && action != "apply" && action != "rollback" {
		return errors.New("upgrade_runtime_phase_invalid")
	}
	transaction := fmt.Sprintf("%s-runtime-%d", lifecycleID(directory), generation)
	requests, err := upgradeRuntimeRequests(p, inspection, inventory, transaction)
	if err != nil {
		return err
	}
	variables := map[string]any{}
	for _, key := range []string{"ultra_lock_directory", "ultra_release_manifest", "ultra_release_source", "ultra_release_version", "ultra_lifecycle_id", "ultra_forward_only"} {
		variables[key] = releaseVariables[key]
	}
	authorizeUpgradeDomainRequest(requests, releaseVariables)
	variables["ultra_runtime_effect_inputs"] = runtimeEffectInputs(requests)
	assets, assetErr := runtimeWarpAssets()
	if assetErr != nil {
		return assetErr
	}
	variables["ultra_runtime_warp_assets"] = assets
	variables["ultra_runtime_probe_requests"], variables["ultra_runtime_action"] = requests, action
	run := deployansible.RunLocal
	if (action == "prepare" || action == "rollback") && len(retryFailed) > 0 && retryFailed[0] {
		run = deployansible.RunLocalRetryFailed
	}
	receipt, err := run(
		ctx,
		"upgrade-runtime",
		inventory,
		variables,
		upgradeDependentStageDirectory(directory, "runtime-"+action, generation),
		python,
		executable,
	)
	if err != nil {
		return err
	}
	if receipt.Result.Values["verified"] != true || receipt.Result.Values["phase"] != action {
		return errors.New("upgrade_runtime_phase_unverified")
	}
	raw, err := json.Marshal(receipt.Result.Values["hosts"])
	var hosts map[string]runtimeProbeResult
	if err != nil || json.Unmarshal(raw, &hosts) != nil || len(hosts) != len(requests) {
		return errors.New("upgrade_runtime_phase_unverified")
	}
	for host := range requests {
		result, found := hosts[host]
		if !found || !result.Verified || (action == "prepare" && result.Status != "prepared" && result.Status != "applied") ||
			(action == "apply" && result.Status != "applied") ||
			(action == "rollback" && result.Status != "rolled_back") {
			return errors.New("upgrade_runtime_phase_unverified")
		}
	}
	return nil
}

func inspectUpgradeDesiredRuntime(
	ctx context.Context,
	p *installplan.InstallPlan,
	inspection upgradeInspection,
	inventory, releaseVariables map[string]any,
	directory, python, executable string,
) error {
	requests, err := upgradeRuntimeRequests(p, inspection, inventory, lifecycleID(directory))
	if err != nil {
		return err
	}
	variables := map[string]any{}
	for _, key := range []string{"ultra_lock_directory", "ultra_release_manifest", "ultra_release_source", "ultra_release_version"} {
		variables[key] = releaseVariables[key]
	}
	authorizeUpgradeDomainRequest(requests, releaseVariables)
	variables["ultra_runtime_effect_inputs"] = runtimeEffectInputs(requests)
	assets, assetErr := runtimeWarpAssets()
	if assetErr != nil {
		return assetErr
	}
	variables["ultra_runtime_warp_assets"] = assets
	variables["ultra_runtime_probe_requests"] = requests
	receipt, err := runUpgradeInspection(
		ctx,
		"inspect-upgrade-runtime",
		inventory,
		variables,
		filepath.Join(directory, "runtime-inspect"),
		python,
		executable,
	)
	if err != nil {
		return err
	}
	return validateUpgradeRuntimeEvidence(receipt.Result.Values, requests)
}

func validateUpgradeRuntimeEvidence(values map[string]any, requests map[string]any) error {
	raw, err := json.Marshal(values)
	if err != nil {
		return errors.New("upgrade_runtime_evidence_invalid")
	}
	var result struct {
		Verified bool                          `json:"verified"`
		Hosts    map[string]runtimeProbeResult `json:"hosts"`
	}
	if json.Unmarshal(raw, &result) != nil || !result.Verified || len(result.Hosts) != len(requests) {
		return errors.New("upgrade_runtime_evidence_invalid")
	}
	for host := range requests {
		evidence, ok := result.Hosts[host]
		if !ok || !evidence.Verified {
			return errors.New("upgrade_runtime_evidence_invalid")
		}
		request, _ := requests[host].(runtimeProbeInput)
		if evidence.DomainChanged && (host != "bridge" || !runtimeHostValidDigest(request.DomainTransaction)) {
			return errors.New("upgrade_domain_acceptance_transaction_required")
		}
		for _, transition := range evidence.Transitions {
			switch transition {
			case installplan.RuntimeTransitionTLS,
				installplan.RuntimeTransitionWARP,
				installplan.RuntimeTransitionListener,
				installplan.RuntimeTransitionTunnel:
				if !evidence.EffectsReady {
					return errors.New("upgrade_runtime_effect_checkpoint_required")
				}
			default:
				return errors.New("upgrade_runtime_evidence_invalid")
			}
		}
	}
	return nil
}

func authorizeUpgradeDomainRequest(requests, releaseVariables map[string]any) {
	binding, _ := releaseVariables["ultra_upgrade_domain_binding"].(string)
	if runtimeHostValidDigest(binding) {
		if bridge, ok := requests["bridge"].(runtimeProbeInput); ok {
			bridge.DomainTransaction = binding
			requests["bridge"] = bridge
		}
	}
}

func runtimeWarpAssets() (map[string]string, error) {
	assets := map[string]string{}
	for target, source := range map[string]string{
		"/usr/local/bin/ultra-warp-watchdog":              "roles/warp/files/ultra-warp-watchdog",
		"/etc/systemd/system/ultra-warp-watchdog.service": "roles/warp/templates/ultra-warp-watchdog.service.j2",
		"/etc/systemd/system/ultra-warp-watchdog.timer":   "roles/warp/templates/ultra-warp-watchdog.timer.j2",
	} {
		raw, err := ansibleassets.Bundle.ReadFile(source)
		if err != nil {
			return nil, err
		}
		assets[target] = string(raw)
	}
	return assets, nil
}

// Invoke only after release commit and domain retirement, under the fleet lease.
// It seals newly owned firewall grants; old rules without receipts are retained.
func runUpgradeRuntimeEffectsCommit(
	ctx context.Context,
	p *installplan.InstallPlan,
	inspection upgradeInspection,
	inventory, releaseVariables map[string]any,
	directory, python, executable string,
	generation int,
) error {
	requests, err := upgradeRuntimeRequests(p, inspection, inventory, fmt.Sprintf("%s-runtime-%d", lifecycleID(directory), generation))
	if err != nil {
		return err
	}
	authorizeUpgradeDomainRequest(requests, releaseVariables)
	assets, err := runtimeWarpAssets()
	if err != nil {
		return err
	}
	variables := map[string]any{
		"ultra_lock_directory":         releaseVariables["ultra_lock_directory"],
		"ultra_release_manifest":       releaseVariables["ultra_release_manifest"],
		"ultra_runtime_probe_requests": requests,
		"ultra_runtime_effect_inputs":  runtimeEffectInputs(requests),
		"ultra_runtime_warp_assets":    assets,
		"ultra_runtime_action":         "commit",
	}
	receipt, err := deployansible.RunLocalRetryFailed(
		ctx,
		"upgrade-runtime",
		inventory,
		variables,
		upgradeDependentStageDirectory(directory, "runtime-effects-commit", generation),
		python,
		executable,
	)
	if err != nil {
		return err
	}
	if receipt.Result.Values["verified"] != true || receipt.Result.Values["phase"] != "commit" {
		return errors.New("upgrade_runtime_effect_commit_unverified")
	}
	return nil
}

// Binary rollback finishes by restoring the exact runtime effect service state.
// The same immutable request binds this final compensation to its host journal.
func runUpgradeReleaseRollback(
	ctx context.Context,
	p *installplan.InstallPlan,
	inspection upgradeInspection,
	inventory, releaseVariables map[string]any,
	directory, python, executable string,
	generation int,
	retryFailed bool,
) error {
	requests, err := upgradeRuntimeRequests(p, inspection, inventory, fmt.Sprintf("%s-runtime-%d", lifecycleID(directory), generation))
	if err != nil {
		return err
	}
	authorizeUpgradeDomainRequest(requests, releaseVariables)
	assets, err := runtimeWarpAssets()
	if err != nil {
		return err
	}
	variables := map[string]any{}
	for key, value := range releaseVariables {
		variables[key] = value
	}
	variables["ultra_runtime_effect_inputs"] = runtimeEffectInputs(requests)
	variables["ultra_legacy_initial_runtime_request_json"] = runtimeEffectInputs(requests)["bridge"]
	variables["ultra_runtime_warp_assets"] = assets
	run := deployansible.RunLocal
	if retryFailed {
		run = deployansible.RunLocalRetryFailed
	}
	receipt, err := run(
		ctx,
		"rollback",
		inventory,
		variables,
		upgradeDependentStageDirectory(directory, "rollback", generation),
		python,
		executable,
	)
	if err != nil {
		return err
	}
	if receipt.Result.Values["verified"] != true {
		return errors.New("upgrade_release_rollback_unverified")
	}
	return nil
}
