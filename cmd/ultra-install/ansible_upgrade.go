package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	ansibleassets "github.com/NikitaDmitryuk/ultra/deploy/ansible"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

type upgradeInspection struct {
	DatabaseSchema      int                                   `json:"database_schema"`
	ControllerDirectory string                                `json:"controller_directory"`
	ControllerUnitSHA   string                                `json:"controller_unit_sha256"`
	ToolIdentityHashes  map[string]string                     `json:"tool_identity_hashes"`
	ToolHashes          map[string]string                     `json:"tool_hashes"`
	AutoPolicy          map[string]any                        `json:"auto_policy"`
	ObservedAt          int64                                 `json:"observed_at"`
	ActiveRelaySHA256   string                                `json:"active_relay_sha256"`
	Architecture        string                                `json:"architecture"`
	TopologySHA         string                                `json:"topology_sha256"`
	Identity            string                                `json:"identity"`
	PreviousManifestSHA string                                `json:"previous_manifest_sha256"`
	Previous            automationRelease                     `json:"previous_manifest"`
	RuntimeNodes        map[string]upgradeRuntimeNodeEvidence `json:"runtime_nodes"`
	Nodes               []struct {
		ID      string `json:"id"`
		Address string `json:"address"`
		Pins    string `json:"pins"`
	} `json:"nodes"`
}

// Upgrade retains a frozen private job directory across process/SSH failures.
// It never falls back to the former SSH installer after an Ansible error.
func ansibleUpgrade(
	ctx context.Context,
	p *installplan.InstallPlan,
	releaseDir, directory, python, executable string,
	retryFailed bool,
	forwardOnlyOption ...bool,
) (returnErr error) {
	if p != nil && p.Features.MainExitDomain != "" &&
		(p.SchemaVersion != 2 || p.SourceValues == nil || p.AdoptRuntime || p.Bridge.ReuseSpec ||
			p.Automation == nil || p.Automation.DNS == nil || p.Automation.Ingress == nil ||
			p.Automation.Ingress.ForwardHost != "" || len(p.Exits) != 1 ||
			(len(forwardOnlyOption) > 0 && forwardOnlyOption[0])) {
		return errors.New("upgrade_managed_tunnel_preservation_envelope_required")
	}
	forwardOnly := len(forwardOnlyOption) == 1 && forwardOnlyOption[0]
	if len(forwardOnlyOption) > 1 || (forwardOnly && retryFailed) {
		return errors.New("upgrade_forward_only_arguments_invalid")
	}
	if err := installplan.ValidatePlan(p); err != nil {
		return err
	}
	if releaseDir == "" && p.Automation != nil {
		releaseDir = p.Automation.ReleaseDir
	}
	if releaseDir != "" {
		absolute, err := filepath.Abs(releaseDir)
		if err != nil {
			return err
		}
		releaseDir = absolute
	}
	// Exact completed replay uses surviving metadata before removed release inputs.
	if directory != "" {
		absolute, err := filepath.Abs(directory)
		if err != nil {
			return err
		}
		if cached, err := completedOperatorOperation(absolute, "upgrade", ""); cached {
			if err != nil {
				return err
			}
			if err = matchOperatorPlan(absolute, p, releaseDir); err != nil {
				return err
			}
			return matchCompletedOperatorRelease(absolute, releaseDir)
		}
	}
	manifest, err := verifyAutomationRelease(releaseDir, "")
	if err != nil {
		return err
	}
	releaseDir, err = filepath.Abs(releaseDir)
	if err != nil {
		return err
	}
	if directory == "" && os.Geteuid() == 0 {
		directory = filepath.Join("/var/lib/ultra-ansible", "upgrade-"+manifest.Version)
	}
	if directory == "" {
		cache, err := os.UserCacheDir()
		if err != nil {
			return err
		}
		directory = filepath.Join(cache, "ultra-ansible", "upgrade-"+manifest.Version)
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	if err = freezeOperatorPlan(directory, p, releaseDir); err != nil {
		return err
	}
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		return err
	}
	if err = pinOperatorRelease(filepath.Join(cacheRoot, "ultra", "releases"), directory, releaseDir); err != nil {
		return errors.New("upgrade_release_retention_pin_failed")
	}
	originalCtx := ctx
	operatorCtx, releaseOperator, err := withBootstrapOperatorLock(ctx, filepath.Dir(directory))
	if err != nil {
		return err
	}
	defer releaseOperator()
	lockDirectory, err := freezeBootstrapExecution(p, directory, filepath.Dir(directory))
	if err != nil {
		return err
	}
	runtimePlan := *p
	if p.Automation != nil {
		automation := *p.Automation
		automation.ReleaseDir = releaseDir
		automation.Version = manifest.Version
		runtimePlan.Automation = &automation
	}
	executable, err = resolveAnsibleRuntime(ctx, &runtimePlan, lockDirectory, executable)
	if err != nil {
		return err
	}
	runtimeRelease, err := pinOperatorRuntimeForOperation(directory, executable)
	if err != nil {
		return err
	}
	defer runtimeRelease()
	inventory, err := upgradeInventory(p, directory)
	if err != nil {
		return err
	}
	// Resumed/forward attempts may own a durable applying reservation already.
	// Their recovery protocol must run before reconcile can refresh readiness.
	if !forwardOnly && !retryFailed {
		_, activationErr := os.Lstat(filepath.Join(directory, "activate", "job.json"))
		if os.IsNotExist(activationErr) {
			reserved, reservationErr := upgradeHasApplyingReservation(
				p,
				directory,
				lockDirectory,
				inventory,
			)
			if reservationErr != nil {
				return reservationErr
			}
			if !reserved || !localLifecycleBridge(p) {
				pending := upgradeApplyingReservationPending(directory)
				if err = deployansible.WaitUpgradeReadiness(originalCtx, inventory, lockDirectory, python, executable, lifecycleID(directory), pending, directory); err != nil {
					return err
				}
			}
		} else if activationErr != nil {
			return activationErr
		}
	}
	var releaseLock func()
	if forwardOnly {
		ctx, releaseLock, err = withForwardUpgradeHandoff(operatorCtx, p, lockDirectory, directory, python, executable)
	} else {
		ctx, releaseLock, err = withFrozenLifecycleLock(operatorCtx, p, lockDirectory, directory)
	}
	if err != nil {
		return err
	}
	lockHeld := true
	forwardReleaseComplete := false
	if forwardOnly {
		defer func() {
			if returnErr == nil || forwardReleaseComplete {
				return
			}
			returnErr = errors.Join(returnErr, containForwardUpgradeFailure(operatorCtx, forwardMaintenanceDeps{
				attach: func(cleanup context.Context) (context.Context, func(), error) {
					cleanup, release, leaseErr := withFrozenLifecycleLock(cleanup, p, lockDirectory, directory)
					if leaseErr != nil {
						return cleanup, nil, leaseErr
					}
					if leaseErr = (deployansible.Client{Socket: lifecycleSocket()}).ResumeLifecycleWithOperationLock(cleanup, lifecycleID(directory)); leaseErr != nil {
						release()
						return cleanup, nil, leaseErr
					}
					return cleanup, release, nil
				},
				stop: func(cleanup context.Context) error {
					proof, ok := operatorCtx.Value(forwardUpgradeJournalKey{}).(forwardUpgradeJournal)
					if !ok {
						return errors.New("upgrade_forward_maintenance_fleet_unverified")
					}
					old, proofErr := discoverForwardOldOperation(proof, lockDirectory)
					if proofErr != nil {
						return proofErr
					}
					return stopForwardUpgradeFleet(cleanup, old.Inventory, lockDirectory, directory, python, executable)
				},
			}))
		}()
	}
	defer func() {
		if lockHeld {
			releaseLock()
		}
	}()
	var enforcement map[string]any
	var preparedControllerPolicy map[string]any
	if !forwardOnly {
		enforcement, err = upgradeEnforcementSpec(directory, releaseDir, manifest, inventory)
		if err != nil {
			return err
		}
		if completed, completionErr := recoverEnforcementCompletion(ctx, p, directory, lockDirectory, python, executable, manifest, inventory, enforcement); completionErr != nil ||
			completed {
			return completionErr
		}
		preparedControllerPolicy, err = recoveryPreparedControllerPolicy(ctx, p, directory, releaseDir, inventory, enforcement)
		if err != nil {
			return err
		}
		if len(preparedControllerPolicy) > 0 {
			enforcement["prepared_policy"] = preparedControllerPolicy
		}
		// Probe both exact broker executables in isolated state before reserving
		// production. A fresh receipt is required even when a proof is retained.
		if err = runEnforcementPreflight(ctx, inventory, directory, lockDirectory, python, executable, enforcement); err != nil {
			return err
		}
	}
	baselineInput, err := prepareUpgradeBaseline(p.SourceValues["ULTRA_UPGRADE_BASELINE_FILE"], directory)
	if err != nil {
		return err
	}
	legacyBridgeMaintenance := false
	legacyBridgeSHA := ""
	resumeCompleted := false
	preActivation := true
	var domainTransaction *upgradeDomainTransaction
	domainPrepareAttempted := false
	managedTunnelPrepareAttempted := false
	domainGeneration := 0
	var acceptedResume map[string]any
	// A separate attempt always resumes timers, including after UNREACHABLE.
	resume := func(cleanup context.Context) error {
		resumeDirectory, err := os.MkdirTemp(directory, "resume-")
		if err == nil {
			_ = os.Remove(resumeDirectory)
			variables := upgradeResumeVariables(
				lockDirectory,
				lifecycleID(directory),
				legacyBridgeMaintenance,
				legacyBridgeSHA,
				acceptedResume,
			)
			if len(preparedControllerPolicy) > 0 {
				variables["ultra_prepared_controller_policy"] = preparedControllerPolicy
				variables["ultra_controller_enforcement_spec"] = enforcement
			}
			_, err = deployansible.RunLocal(cleanup, "resume-automation", inventory, variables, resumeDirectory, python, executable)
			if err == nil {
				resumeCompleted = true
			}
		}
		return err
	}
	// Before the first activation, an inspection failure has no release mutation
	// to roll back. Recover schedules and the durable gate while retaining the
	// lease and every inspection receipt. A surviving activation job instead
	// belongs to the existing compatible rollback/retry protocol.
	_, activationStateErr := os.Lstat(filepath.Join(directory, "activate", "job.json"))
	if activationStateErr != nil && !os.IsNotExist(activationStateErr) {
		return activationStateErr
	}
	if forwardOnly && activationStateErr == nil {
		return errors.New("upgrade_forward_only_requires_fresh_operation")
	}
	// Reserve first, then install same-ID recovery before inspection or drain can
	// fail. A failed or ambiguous reservation response never authorizes cleanup.
	reservation, reserveErr := ansibleLifecycleReserve(ctx, p, inventory, directory, python, executable, "applying")
	if reserveErr != nil {
		return reserveErr
	}
	if values := reservation.Result.Values; values["verified"] != true || values["reservation_id"] != lifecycleID(directory) ||
		values["reservation_phase"] != "applying" {
		return errors.New("upgrade_lifecycle_reservation_unverified")
	}
	defer func() {
		if forwardOnly || !preActivation || returnErr == nil || !os.IsNotExist(activationStateErr) {
			return
		}
		if managedTunnelPrepareAttempted {
			// A failed preparation can retain private native/effect images. Keep
			// renewal and the fleet reservation excluded for the exact retry;
			// no candidate executable has been activated yet.
			returnErr = errors.Join(returnErr, errors.New("upgrade_managed_tunnel_preparation_requires_retry"))
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
		if domainPrepareAttempted {
			if domainErr := domainTransaction.phase(cleanup, inventory, directory, python, executable, "rollback-dns", domainGeneration); domainErr != nil {
				returnErr = errors.Join(returnErr, errors.New("upgrade_domain_preparation_rollback_incomplete"))
				return
			}
		}
		if err := resume(cleanup); err != nil {
			returnErr = errors.Join(returnErr, errors.New("upgrade_automation_resume_failed"))
			return
		}
		if len(preparedControllerPolicy) == 0 {
			if err := ansibleLifecycle(cleanup, p, inventory, directory, python, executable, "released", false); err != nil {
				returnErr = errors.Join(returnErr, err)
			}
		}
	}()
	if enforcement != nil {
		enforcement["phase"] = "reserved"
		if err = runEnforcementPreflight(ctx, inventory, directory, lockDirectory, python, executable, enforcement); err != nil {
			return err
		}
	}
	inspectionVariables := map[string]any{"ultra_lock_directory": lockDirectory}
	if len(preparedControllerPolicy) > 0 {
		inspectionVariables["ultra_controller_enforcement_spec"] = enforcement
	}
	inspectionReceipt, err := runUpgradeInspection(
		ctx,
		"inspect-upgrade",
		inventory,
		inspectionVariables,
		filepath.Join(directory, "inspect"),
		python,
		executable,
	)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(inspectionReceipt.Result.Values)
	if err != nil {
		return err
	}
	var inspection upgradeInspection
	if err = json.Unmarshal(raw, &inspection); err != nil {
		return errors.New("upgrade_inspection_invalid")
	}
	if enforcement != nil {
		if proof, _ := enforcement["proof"].(map[string]any); len(proof) != 0 {
			rollback, _ := proof["rollback"].(map[string]any)
			if (rollback["directory"] != inspection.ControllerDirectory || rollback["unit_sha256"] != inspection.ControllerUnitSHA) &&
				!recoveryBrokerInspectionMatches(preparedControllerPolicy, inspection, enforcement) {
				return errors.New("upgrade_controller_enforcement_rollback_changed")
			}
		}
	}
	if forwardOnly {
		// The active bridge bytes are explicitly known to differ from the last
		// signed release. Validate the signed target and its DB schema below,
		// without representing unknown active bytes as a rollback candidate.
	} else if err = compatibleAnsibleRelease(&inspection.Previous, manifest); err != nil {
		return err
	}
	if inspection.DatabaseSchema < manifest.DatabaseSchemaMin || inspection.DatabaseSchema > manifest.DatabaseSchemaMax {
		return errors.New("upgrade_database_schema_incompatible")
	}
	if inspection.Architecture != "amd64" && inspection.Architecture != "arm64" {
		return errors.New("upgrade_architecture_invalid")
	}
	if inspection.ObservedAt <= 0 || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(inspection.TopologySHA) ||
		len(inspection.Nodes) == 0 ||
		len(inspection.Nodes) > 16 ||
		inspection.Identity == "" {
		return errors.New("upgrade_topology_invalid")
	}
	nodes, err := freezeUpgradeExits(inspection, directory)
	if err != nil {
		return err
	}
	all := inventory["all"].(map[string]any)
	children := all["children"].(map[string]any)
	children["exits"] = map[string]any{"hosts": nodes}
	inspectionDirectory := filepath.Join(directory, "architectures")
	if err = os.MkdirAll(inspectionDirectory, 0700); err != nil {
		return err
	}
	hostVariables := map[string]any{"ultra_lock_directory": lockDirectory, "ultra_release_inspection_directory": inspectionDirectory}
	if baselineInput != nil {
		baselineNodes := map[string]any{}
		for _, node := range inspection.Nodes {
			baselineNodes[node.ID] = map[string]any{"address": node.Address, "pins": node.Pins}
		}
		hostVariables["ultra_upgrade_baseline_input"] = baselineInput
		hostVariables["ultra_upgrade_baseline_nodes"] = baselineNodes
		hostVariables["ultra_upgrade_baseline_bridge_address"] = p.Bridge.SSHHost
	}
	hostReceipt, err := runUpgradeInspection(
		ctx,
		"inspect-release-hosts",
		inventory,
		hostVariables,
		filepath.Join(directory, "hosts"),
		python,
		executable,
	)
	if err != nil {
		return err
	}
	baseline := upgradeBaselineResult{}
	relayPrevious := &inspection.Previous
	if baselineInput != nil {
		raw, marshalErr := json.Marshal(hostReceipt.Result.Values["baseline"])
		if marshalErr != nil || json.Unmarshal(raw, &baseline) != nil {
			return errors.New("upgrade_baseline_result_invalid")
		}
		if err = freezeUpgradeBaseline(baselineInput, baseline, inspection, manifest, directory); err != nil {
			return err
		}
		relayPrevious = &baseline.BridgeRelay
		for _, node := range inspection.Nodes {
			alias := "exit_" + strings.ReplaceAll(node.ID, "-", "")
			nodes[alias].(map[string]any)["ultra_host_previous_manifest"] = baseline.Exits[node.ID]
		}
	}
	previousRelayAsset, previousRelayErr := upgradeAsset(relayPrevious, "ultra-relay-linux-"+inspection.Architecture)
	legacyBridgeMaintenance = !hasAutomationCapability(relayPrevious, "lifecycle-gate-v1")
	if forwardOnly && (previousRelayErr != nil || inspection.ActiveRelaySHA256 != previousRelayAsset.SHA) {
		legacyBridgeMaintenance = true
	}
	if legacyBridgeMaintenance {
		if forwardOnly {
			if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(inspection.ActiveRelaySHA256) {
				return errors.New("upgrade_legacy_bridge_identity_unavailable")
			}
			legacyBridgeSHA = inspection.ActiveRelaySHA256
		} else {
			if previousRelayErr != nil {
				return errors.New("upgrade_legacy_bridge_identity_unavailable")
			}
			legacyBridgeSHA = previousRelayAsset.SHA
		}
	} else if err = ansibleLifecycle(ctx, p, inventory, directory, python, executable, "applying", true); err != nil {
		return err
	}
	bridge := children["bridge"].(map[string]any)["hosts"].(map[string]any)["bridge"].(map[string]any)
	bridge["ultra_architecture"] = inspection.Architecture
	if baselineInput != nil {
		bridge["ultra_previous_relay_manifest"] = baseline.BridgeRelay
	}
	for alias, value := range nodes {
		raw, err := os.ReadFile(filepath.Join(inspectionDirectory, alias+".json"))
		if err != nil {
			return err
		}
		var architecture struct {
			ObservedAt   int64  `json:"observed_at"`
			Architecture string `json:"architecture"`
		}
		if json.Unmarshal(raw, &architecture) != nil || (architecture.Architecture != "amd64" && architecture.Architecture != "arm64") {
			return errors.New("upgrade_architecture_invalid")
		}
		value.(map[string]any)["ultra_architecture"] = architecture.Architecture
	}
	tools, err := extractUpgradeTools(
		filepath.Join(releaseDir, "ultra-recovery.tar.gz"),
		filepath.Join(directory, "recovery-bundle"),
		inspection.ToolHashes,
	)
	if err != nil {
		return err
	}
	if err = requireUpgradeTool(tools, "db_connection.py"); err != nil {
		return err
	}
	if err = requireUpgradeTool(tools, "live_tools.py"); err != nil {
		return err
	}
	toolsManifestSHA, identityErr := sourceSHA(filepath.Join(releaseDir, "release-manifest.json"))
	if identityErr != nil {
		return identityErr
	}
	liveIdentity, identityErr := upgradeLiveToolsIdentity(directory, releaseDir, toolsManifestSHA, tools, inspection.ToolIdentityHashes)
	if identityErr != nil {
		return identityErr
	}
	bridge["ultra_recovery_tools_identity_files"] = liveIdentity
	bridge["ultra_recovery_files"] = tools
	baselineToolHashes := map[string]string{}
	if baselineInput != nil {
		priorTools, toolErr := extractHistoricalUpgradeTools(
			filepath.Join(filepath.Dir(baselineInput.Descriptor.Manifest), "ultra-recovery.tar.gz"),
			filepath.Join(directory, "baseline-tools"),
			nil,
		)
		if toolErr != nil {
			return toolErr
		}
		for _, tool := range priorTools {
			baselineToolHashes[filepath.Base(tool["destination"].(string))] = tool["sha256"].(string)
		}
	}
	for alias, value := range nodes {
		node := value.(map[string]any)
		arch := node["ultra_architecture"].(string)
		selected := []map[string]any{}
		for _, tool := range tools {
			base := filepath.Base(tool["destination"].(string))
			if isExitUpgradeRecoveryTool(base) {
				if baselineInput != nil {
					copy := map[string]any{}
					for key, value := range tool {
						copy[key] = value
					}
					copy["previous_sha256"] = baselineToolHashes[base]
					selected = append(selected, copy)
				} else {
					selected = append(selected, tool)
				}
			}
		}
		previous := &inspection.Previous
		if baselineInput != nil {
			selected := baseline.Exits[node["ultra_exit_id"].(string)]
			previous = &selected
		}
		client, err := upgradeClientTool(manifest, previous, releaseDir, arch)
		if err != nil {
			return err
		}
		selected = append(selected, client)
		node["ultra_recovery_files"] = selected
		nodes[alias] = node
	}
	client, err := upgradeClientTool(manifest, &inspection.Previous, releaseDir, inspection.Architecture)
	if err != nil {
		return err
	}
	bridge["ultra_recovery_files"] = append(tools, client)
	installer, err := upgradeAsset(manifest, "ultra-install-linux-"+inspection.Architecture)
	if err != nil {
		return err
	}
	runtime, err := upgradeAsset(manifest, "ultra-ansible-runtime-linux-"+inspection.Architecture+".tar.gz")
	if err != nil {
		return err
	}
	bridge["ultra_controller_directory"] = managedControllerDirectory(manifest.Version)
	bridge["ultra_install_source"] = filepath.Join(releaseDir, "ultra-install-linux-"+inspection.Architecture)
	bridge["ultra_install_sha256"] = installer.SHA
	bridge["ultra_controller_runtime_archive"] = filepath.Join(releaseDir, "ultra-ansible-runtime-linux-"+inspection.Architecture+".tar.gz")
	bridge["ultra_controller_runtime_sha256"] = runtime.SHA
	controllerUnit, err := ansibleassets.Bundle.ReadFile("roles/controller/templates/ultra-ansible-controller.service.j2")
	if err != nil {
		return err
	}
	controllerRendered := strings.ReplaceAll(
		string(controllerUnit),
		"{{ ultra_controller_directory }}",
		bridge["ultra_controller_directory"].(string),
	)
	controllerHash := sha256.Sum256([]byte(controllerRendered))
	previousControllerDirectory, previousControllerUnitSHA, policyErr := preparedControllerRollbackIdentity(
		preparedControllerPolicy,
		enforcement,
		inspection,
	)
	if policyErr != nil {
		return policyErr
	}
	bridge["ultra_previous_controller_directory"] = previousControllerDirectory
	bridge["ultra_previous_controller_unit_sha256"] = previousControllerUnitSHA
	bridge["ultra_target_controller_unit_sha256"] = hex.EncodeToString(controllerHash[:])
	bridge["ultra_auto_upgrade_policy"] = inspection.AutoPolicy
	bridge["ultra_auto_upgrade_enabled"] = inspection.AutoPolicy["enabled"] == true
	manifestSHA, err := sourceSHA(filepath.Join(releaseDir, "release-manifest.json"))
	if err != nil {
		return err
	}
	variables := map[string]any{
		"ultra_lock_directory":            lockDirectory,
		"ultra_bot_enabled":               p.Bot.Enabled,
		"ultra_upgrade_observed_at":       inspection.ObservedAt,
		"ultra_release_manifest":          manifest,
		"ultra_release_manifest_sha256":   manifestSHA,
		"ultra_previous_manifest_sha256":  inspection.PreviousManifestSHA,
		"ultra_previous_manifest":         inspection.Previous,
		"ultra_release_source":            releaseDir,
		"ultra_release_version":           manifest.Version,
		"ultra_topology_sha256":           inspection.TopologySHA,
		"ultra_bridge_inventory_host":     "bridge",
		"ultra_release_probe_executable":  "/var/lib/ultra-ansible/releases/" + manifest.Version + "/ultra-install",
		"ultra_legacy_bridge_maintenance": legacyBridgeMaintenance,
		"ultra_legacy_bridge_sha256":      legacyBridgeSHA,
		"ultra_lifecycle_id":              lifecycleID(directory),
		"ultra_forward_only":              forwardOnly,
	}
	if enforcement != nil {
		variables["ultra_controller_enforcement_spec"] = enforcement
	}
	if len(preparedControllerPolicy) > 0 {
		variables["ultra_prepared_controller_policy"] = preparedControllerPolicy
	}
	if planSecretsSource(p) != "canonical" {
		variables["ultra_secrets_source"] = planSecretsSource(p)
	}
	frozenInventory, err := json.Marshal(inventory)
	if err != nil {
		return err
	}
	if err = writeUpgradeInput(filepath.Join(directory, "inventory.frozen.json"), frozenInventory); err != nil {
		return err
	}
	// Canonical desired settings must be inspected before binary activation.
	// This operation uses the existing lease and the same pinned fleet inventory.
	// Unsupported migrations are rejected without touching runtime or endpoints.
	domainTransaction, err = inspectUpgradeDomains(ctx, p, inventory, variables, directory, python, executable)
	if err != nil {
		return err
	}
	if domainTransaction.Changed {
		variables["ultra_upgrade_domain_binding"] = domainTransaction.Binding
	}
	// Retire the old experiment while its publisher and bot can refresh the
	// cache. Domain inspection above still has access to legacy port metadata;
	// runtime snapshots and all binary changes below use the retired baseline.
	if err = runUpgradeExperimentalRetirement(ctx, inventory, variables, directory, python, executable, retryFailed); err != nil {
		return err
	}
	committedContinuation := retryFailed && upgradeDomainReleaseCommitted(directory)
	compensationGeneration := 0
	if retryFailed && p.Features.MainExitDomain != "" && !committedContinuation {
		if _, receiptErr := os.Lstat(filepath.Join(directory, "activate", "receipt.json")); receiptErr == nil {
			compensationGeneration, err = upgradeActivationGeneration(directory, true)
			if err != nil {
				return err
			}
		} else if !os.IsNotExist(receiptErr) {
			return receiptErr
		}
	}
	if err = inspectUpgradeRuntimeForPurpose(ctx, p, inspection, inventory, variables, directory, python, executable, compensationGeneration); err != nil {
		return err
	}
	if committedContinuation {
		if err = verifyCommittedUpgradeContinuation(directory, inventory, variables); err != nil {
			return err
		}
	}
	if retryFailed {
		_, activationReceiptErr := os.Lstat(filepath.Join(directory, "activate", "receipt.json"))
		if activationReceiptErr != nil && !os.IsNotExist(activationReceiptErr) {
			return activationReceiptErr
		}
		preflightVariables := make(map[string]any)
		for key, value := range variables {
			preflightVariables[key] = value
		}
		if legacyBridgeMaintenance && activationReceiptErr == nil {
			generation, generationErr := upgradeActivationGeneration(directory, true)
			if generationErr != nil {
				return generationErr
			}
			if !committedContinuation {
				if err = requireFailedUpgradeAttempt(directory, generation); err != nil {
					return err
				}
			}
			contract, contractErr := upgradeAcceptedResumeContract(
				p,
				inspection,
				inventory,
				variables,
				directory,
				domainTransaction,
				generation,
			)
			if contractErr != nil {
				return contractErr
			}
			// The committed chain was verified above. Preserve its accepted
			// runtime/domain image for schedule restoration as well as preflight;
			// retry-only mode/target fields must not cross the resume boundary.
			contract, acceptedResume = upgradeRetryResumeContracts(contract, committedContinuation)
			asset, assetErr := upgradeAsset(manifest, "ultra-relay-linux-"+inspection.Architecture)
			if assetErr != nil {
				return assetErr
			}
			contract["target_sha256"], contract["release_version"] = asset.SHA, manifest.Version
			preflightVariables["ultra_legacy_retry_configuration"] = contract
		}
		preflightDirectory, err := os.MkdirTemp(directory, "retry-preflight-")
		if err != nil {
			return err
		}
		_ = os.Remove(preflightDirectory)
		if _, err = deployansible.RunLocal(ctx, "preflight-retry", inventory, preflightVariables, preflightDirectory, python, executable); err != nil {
			return err
		}
		if activationStateErr == nil && os.IsNotExist(activationReceiptErr) {
			// The controller writes its receipt before any activation mutation.
			// A prepared generation must retain its runtime journals unchanged.
			generation, generationErr := upgradeActivationGeneration(directory, false)
			if generationErr != nil {
				return generationErr
			}
			if generation > 1 {
				if err = resetFailedUpgradeAttempt(directory); err != nil {
					return err
				}
			}
		}
		if activationStateErr == nil && activationReceiptErr == nil && !committedContinuation {
			previousGeneration, generationErr := upgradeActivationGeneration(directory, true)
			if generationErr != nil {
				return generationErr
			}
			if err = requireFailedUpgradeAttempt(directory, previousGeneration); err != nil {
				return err
			}
			// A failed commit can leave the first candidate applied. Restore that
			// attempt's exact baseline before a new generation takes its snapshots.
			untouched, inspectErr := untouchedLegacyUpgrade(
				ctx,
				legacyBridgeMaintenance,
				p,
				inspection,
				inventory,
				variables,
				directory,
				python,
				executable,
				previousGeneration,
			)
			if inspectErr != nil {
				return errors.New("upgrade_legacy_compensation_inspection_failed")
			}
			if !untouched {
				if err = domainTransaction.phase(ctx, inventory, directory, python, executable, "rollback", previousGeneration); err != nil {
					return errors.New("upgrade_retry_domain_rollback_incomplete")
				}
			}
			if err = domainTransaction.phase(ctx, inventory, directory, python, executable, "rollback-dns", previousGeneration); err != nil {
				return errors.New("upgrade_retry_dns_rollback_incomplete")
			}
			if !untouched {
				if err = runUpgradeRuntimePhase(ctx, p, inspection, inventory, variables, directory, python, executable, "rollback", previousGeneration, true); err != nil {
					return errors.New("upgrade_retry_runtime_rollback_incomplete")
				}
			}
			// Release stages bind the successful activation watermark, not the
			// earlier inspection watermark used for a fresh activation.
			rollbackVariables := map[string]any{}
			for key, value := range variables {
				rollbackVariables[key] = value
			}
			raw, readErr := readBootstrapGenerationInput(filepath.Join(directory, "activate", "receipt.json"))
			if readErr == nil {
				var previous deployansible.Receipt
				if json.Unmarshal(raw, &previous) != nil {
					return errors.New("retry_receipt_invalid")
				}
				if previous.State == "succeeded" {
					timestamp, timestampErr := activationTimestamp(previous.Result.Values["activated_at"])
					if timestampErr != nil || timestamp <= 0 {
						return errors.New("upgrade_activation_timestamp_invalid")
					}
					rollbackVariables["ultra_upgrade_observed_at"] = timestamp
				}
			} else if !os.IsNotExist(readErr) {
				return readErr
			}
			if err = runUpgradeReleaseRollback(ctx, p, inspection, inventory, rollbackVariables, directory, python, executable, previousGeneration, true); err != nil {
				return errors.New("upgrade_retry_release_rollback_incomplete")
			}
			if err = resetFailedUpgradeAttempt(directory); err != nil {
				return err
			}
		}
	}
	if compensationGeneration != 0 {
		// Recovery evidence cannot authorize the next generation. Reinspect the
		// actual restored pair after complete rollback/release and generation reset.
		if err = inspectUpgradeDesiredRuntime(ctx, p, inspection, inventory, variables, directory, python, executable); err != nil {
			return err
		}
	}
	defer func() {
		if forwardOnly && returnErr != nil {
			return
		}
		if managedTunnelPrepareAttempted && preActivation && returnErr != nil {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
		if !resumeCompleted {
			if legacyBridgeMaintenance && !preActivation {
				// After legacy services have been stopped, only a verified activation
				// or completed rollback may restore them. Keep the maintenance barrier
				// intact when both paths fail.
				if returnErr == nil {
					returnErr = errors.New("upgrade_legacy_maintenance_unrestored")
				}
			} else if err := resume(cleanup); err != nil {
				returnErr = errors.Join(returnErr, errors.New("upgrade_automation_resume_failed"))
			}
		}
		if returnErr == nil {
			returnErr = sealCompletedOperatorOperation(directory, "upgrade", manifest, manifestSHA)
			if returnErr == nil {
				returnErr = collectCompletedOperatorArtifacts(filepath.Dir(directory), manifest, &inspection.Previous)
			}
			if returnErr == nil {
				if cacheRoot, cacheErr := os.UserCacheDir(); cacheErr == nil {
					if unpinErr := unpinOperatorReleaseReferences(filepath.Join(cacheRoot, "ultra", "releases"), directory); unpinErr != nil {
						_, _ = fmt.Fprintf(os.Stderr, "warning: release cache pin cleanup skipped: %v\n", unpinErr)
					}
				} else {
					_, _ = fmt.Fprintf(os.Stderr, "warning: release cache pin cleanup skipped: %v\n", cacheErr)
				}
			}
			if returnErr == nil {
				key := strings.TrimSpace(p.SourceValues["ULTRA_RELEASE_MINISIGN_PUBLIC_KEY"])
				if key != "" {
					cache, cacheErr := os.UserCacheDir()
					if cacheErr == nil {
						minisignPath, signerErr := resolveMinisignExecutable()
						cacheErr = signerErr
						if cacheErr == nil {
							keep := []string{manifest.Version}
							if stableReleaseTag.MatchString(inspection.Previous.Version) {
								keep = append(keep, inspection.Previous.Version)
							}
							cacheErr = pruneVerifiedOperatorReleaseCache(
								filepath.Join(cache, "ultra", "releases"), filepath.Dir(directory),
								key, minisignPath, keep...,
							)
						}
					}
					if cacheErr != nil {
						_, _ = fmt.Fprintf(os.Stderr, "warning: release cache retention skipped: %v\n", cacheErr)
					}
				}
			}
		}
	}()
	generation, err := upgradeActivationGeneration(directory, false)
	if err != nil {
		return err
	}
	domainGeneration = generation
	resumeBeforeRelease := func(cleanup context.Context) error {
		if resumeCompleted {
			return nil
		}
		if committedContinuation {
			variables := upgradeResumeVariables(
				lockDirectory,
				lifecycleID(directory),
				legacyBridgeMaintenance,
				legacyBridgeSHA,
				acceptedResume,
			)
			complete, resumeErr := successfulUpgradeResume(directory, inventory, variables)
			if resumeErr != nil {
				return resumeErr
			}
			if complete {
				resumeCompleted = true
				return nil
			}
		}
		return resume(cleanup)
	}
	if committedContinuation {
		// The accepted release already owns these runtime/domain images. Never
		// rerun preparation, activation, publication, readiness, or compensation.
		preActivation = false
		return finishUpgradeCommit(
			ctx,
			p,
			inspection,
			inventory,
			variables,
			directory,
			python,
			executable,
			domainTransaction,
			resumeBeforeRelease,
			generation,
			retryFailed,
			manifest.Version,
		)
	}
	if domainTransaction.Changed {
		domainPrepareAttempted = true
		if err = domainTransaction.phase(ctx, inventory, directory, python, executable, "prepare", generation); err != nil {
			return err
		}
	}
	managedTunnelPrepareAttempted = p.Features.MainExitDomain != ""
	if err = runUpgradeRuntimePhase(ctx, p, inspection, inventory, variables, directory, python, executable, "prepare", generation, retryFailed); err != nil {
		return err
	}
	preActivation = false
	activation, activationErr := deployansible.RunLocal(
		ctx,
		"upgrade",
		inventory,
		variables,
		filepath.Join(directory, "activate"),
		python,
		executable,
	)
	err = activationErr
	if err == nil {
		timestamp, parseErr := activationTimestamp(activation.Result.Values["activated_at"])
		if parseErr != nil || timestamp <= 0 {
			err = errors.New("upgrade_activation_timestamp_invalid")
		} else {
			variables["ultra_upgrade_observed_at"] = timestamp
		}
	}
	if err == nil {
		err = runUpgradeRuntimePhase(ctx, p, inspection, inventory, variables, directory, python, executable, "apply", generation)
	}
	if err == nil {
		err = domainTransaction.phase(ctx, inventory, directory, python, executable, "apply", generation)
	}
	if err == nil {
		_, err = deployansible.RunLocal(
			ctx,
			"publish-release",
			inventory,
			variables,
			upgradeDependentStageDirectory(directory, "publish", generation),
			python,
			executable,
		)
	}
	if err == nil {
		if legacyBridgeMaintenance {
			acceptedResume, err = upgradeAcceptedResumeContract(
				p,
				inspection,
				inventory,
				variables,
				directory,
				domainTransaction,
				generation,
			)
		}
	}
	if err == nil {
		err = resume(ctx)
		if err == nil {
			err = ansibleLifecycle(ctx, p, inventory, directory, python, executable, "checking", false)
		}
		if err == nil {
			releaseLock()
			lockHeld = false
			ctx = originalCtx
			envelope, _, _, supervisorErr := runningDeployReconcileRequest()
			if supervisorErr != nil {
				err = supervisorErr
			} else if envelope != nil {
				err = runDeployPostActivationReconcile(ctx, envelope.Args)
			}

			if err == nil {
				readinessTimeout := 900 * time.Second
				if p.Automation != nil && p.Automation.ReadinessTimeoutSec > 0 {
					readinessTimeout = time.Duration(p.Automation.ReadinessTimeoutSec) * time.Second
				}
				deadline := time.Now().Add(readinessTimeout)
				for {
					verifyDirectory, createErr := os.MkdirTemp(directory, "verify-")
					if createErr != nil {
						err = createErr
						break
					}
					_ = os.Remove(verifyDirectory)
					_, err = deployansible.RunLocal(ctx, "verify-release", inventory, variables, verifyDirectory, python, executable)
					if err == nil {
						break
					}
					if time.Now().After(deadline) {
						err = errors.New("upgrade_post_activation_readiness_failed")
						break
					}
					select {
					case <-ctx.Done():
						err = ctx.Err()
					case <-time.After(5 * time.Second):
						continue
					}
					break
				}
			}
		}
	}

	if err != nil {
		if forwardOnly {
			// The operator explicitly chose forward-only recovery. Preserve the
			// DB and maintenance barrier; never restore unknown pre-upgrade code.
			return fmt.Errorf("upgrade_forward_only_activation_failed: %w", err)
		}
		cleanupParent := operatorCtx
		if lockHeld {
			cleanupParent = ctx
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(cleanupParent), 15*time.Minute)
		defer cancel()
		if !lockHeld {
			var leaseErr error
			cleanup, releaseLock, leaseErr = withFrozenLifecycleLock(cleanup, p, lockDirectory, directory)
			if leaseErr != nil {
				return errors.Join(err, errors.New("upgrade_rollback_lease_unavailable"))
			}
			lockHeld = true
		}
		if leaseErr := ansibleResumeFrozenLifecycle(cleanup, p, inventory, directory, python, executable); leaseErr != nil {
			return errors.Join(err, leaseErr)
		}
		untouched, inspectErr := untouchedLegacyUpgrade(
			cleanup,
			legacyBridgeMaintenance,
			p,
			inspection,
			inventory,
			variables,
			directory,
			python,
			executable,
			generation,
		)
		if inspectErr != nil {
			return errors.Join(err, errors.New("upgrade_legacy_compensation_inspection_failed"))
		}
		if !untouched {
			if domainErr := domainTransaction.phase(cleanup, inventory, directory, python, executable, "rollback", generation); domainErr != nil {
				return errors.Join(err, errors.New("upgrade_domain_rollback_incomplete"))
			}
		}
		if domainErr := domainTransaction.phase(cleanup, inventory, directory, python, executable, "rollback-dns", generation); domainErr != nil {
			return errors.Join(err, errors.New("upgrade_dns_rollback_incomplete"))
		}
		if !untouched {
			if runtimeErr := runUpgradeRuntimePhase(cleanup, p, inspection, inventory, variables, directory, python, executable, "rollback", generation); runtimeErr != nil {
				return errors.Join(err, errors.New("upgrade_runtime_rollback_incomplete"))
			}
		}
		rollbackErr := runUpgradeReleaseRollback(
			cleanup,
			p,
			inspection,
			inventory,
			variables,
			directory,
			python,
			executable,
			generation,
			false,
		)
		if rollbackErr != nil {
			return errors.Join(err, errors.New("upgrade_compatible_rollback_incomplete"))
		}
		if legacyBridgeMaintenance {
			resumeCompleted = true // rollback restores the exact checkpointed bot/timer states
		}
		if len(preparedControllerPolicy) == 0 {
			if gateErr := ansibleLifecycle(cleanup, p, inventory, directory, python, executable, "released", false); gateErr != nil {
				return errors.Join(err, gateErr)
			}
		}
		return err
	}
	// Readiness checks release the fleet lock so background checks can progress.
	// Publication and retention mutate infrastructure and must own it again.
	if !lockHeld {
		ctx, releaseLock, err = withFrozenLifecycleLock(operatorCtx, p, lockDirectory, directory)
		if err != nil {
			return errors.New("upgrade_commit_lease_unavailable")
		}
		lockHeld = true
	}
	err = domainTransaction.phase(ctx, inventory, directory, python, executable, "accept", generation)
	if err == nil {
		_, err = deployansible.RunLocal(
			ctx,
			"commit-release",
			inventory,
			variables,
			upgradeDependentStageDirectory(directory, "commit", generation),
			python,
			executable,
		)
	}
	if err != nil {
		if forwardOnly {
			return fmt.Errorf("upgrade_forward_only_commit_failed: %w", err)
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Minute)
		defer cancel()
		if rollbackErr := domainTransaction.phase(cleanup, inventory, directory, python, executable, "rollback", generation); rollbackErr != nil {
			return errors.Join(err, errors.New("upgrade_domain_commit_rollback_incomplete"))
		}
		if rollbackErr := domainTransaction.phase(cleanup, inventory, directory, python, executable, "rollback-dns", generation); rollbackErr != nil {
			return errors.Join(err, errors.New("upgrade_dns_commit_rollback_incomplete"))
		}
		if rollbackErr := runUpgradeRuntimePhase(cleanup, p, inspection, inventory, variables, directory, python, executable, "rollback", generation); rollbackErr != nil {
			return errors.Join(err, errors.New("upgrade_runtime_commit_rollback_incomplete"))
		}
		if rollbackErr := runUpgradeReleaseRollback(cleanup, p, inspection, inventory, variables, directory, python, executable, generation, false); rollbackErr != nil {
			return errors.Join(err, errors.New("upgrade_release_commit_rollback_incomplete"))
		}
		if len(preparedControllerPolicy) == 0 {
			if gateErr := ansibleLifecycle(cleanup, p, inventory, directory, python, executable, "released", false); gateErr != nil {
				return errors.Join(err, gateErr)
			}
		}
		return err
	}
	err = finishUpgradeCommit(
		ctx,
		p,
		inspection,
		inventory,
		variables,
		directory,
		python,
		executable,
		domainTransaction,
		resumeBeforeRelease,
		generation,
		retryFailed,
		manifest.Version,
	)
	forwardReleaseComplete = err == nil
	return err
}

// Only exact durable reservation evidence suppresses the optional unlocked wait.
// Recovery still acquires its normal lease and repeats strict inspection.
func upgradeHasApplyingReservation(
	p *installplan.InstallPlan,
	directory, lockDirectory string,
	inventory map[string]any,
) (bool, error) {
	if localLifecycleBridge(p) {
		return verifyForwardApplying(lockDirectory, lifecycleID(directory)) == nil, nil
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return false, err
	}
	variables := map[string]any{
		"ultra_lifecycle_id": lifecycleID(directory), "ultra_lifecycle_phase": "applying",
		"ultra_lifecycle_drain": false, "ultra_lifecycle_reserve_only": true,
	}
	reserved := false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "lifecycle-applying-") {
			continue
		}
		stage := filepath.Join(directory, entry.Name())
		if err := operatorPrivate(stage, true); err != nil {
			return false, errors.New("upgrade_readiness_reservation_unverified")
		}
		raw, readErr := readBootstrapGenerationInput(filepath.Join(stage, "receipt.json"))
		var receipt deployansible.Receipt
		if readErr != nil || json.Unmarshal(raw, &receipt) != nil || receipt.State != "succeeded" {
			continue
		}
		// Drain and reserve-only transitions share the directory prefix. Verify
		// each successful receipt against its own exact request purpose.
		request, readErr := readBootstrapGenerationInput(filepath.Join(stage, "request.json"))
		var input struct {
			Inventory map[string]any `json:"inventory"`
			Variables map[string]any `json:"variables"`
		}
		if readErr != nil || json.Unmarshal(request, &input) != nil {
			return false, errors.New("upgrade_readiness_reservation_unverified")
		}
		purpose := variables
		stageInventory := inventory
		if input.Variables["ultra_lifecycle_drain"] == true &&
			input.Variables["ultra_lifecycle_reserve_only"] == false {
			if !upgradeLifecycleDrainInventoryMatches(input.Inventory, inventory, directory) {
				return false, errors.New("upgrade_readiness_reservation_unverified")
			}
			stageInventory = input.Inventory
			purpose = map[string]any{
				"ultra_lifecycle_id":           lifecycleID(directory),
				"ultra_lifecycle_phase":        "applying",
				"ultra_lifecycle_drain":        true,
				"ultra_lifecycle_reserve_only": false,
			}
		}
		if err := verifyBootstrapComponentReceipt(stage, "lifecycle", stageInventory, purpose); err != nil {
			return false, errors.New("upgrade_readiness_reservation_unverified")
		}
		if purpose["ultra_lifecycle_reserve_only"] == false {
			continue
		}
		if receipt.Result.Values["reservation_id"] != lifecycleID(directory) ||
			receipt.Result.Values["reservation_phase"] != "applying" {
			return false, errors.New("upgrade_readiness_reservation_unverified")
		}
		reserved = true
	}
	return reserved, nil
}

// Drain runs after discovered exits (including optional baseline manifests) are
// added, but before bridge variables change. Its fixed playbook targets bridge
// only. Permit isolated exit hosts, preserving every bridge/common/group value;
// a bridge alias or exit group vars/children could alter that target's execution.
func upgradeLifecycleDrainInventoryMatches(
	recorded, expected map[string]any,
	directory string,
) bool {
	raw, err := json.Marshal(recorded)
	if err != nil {
		return false
	}
	var normalized map[string]any
	if json.Unmarshal(raw, &normalized) != nil {
		return false
	}
	all, _ := normalized["all"].(map[string]any)
	children, _ := all["children"].(map[string]any)
	exits, _ := children["exits"].(map[string]any)
	hosts, ok := exits["hosts"].(map[string]any)
	if !ok || len(exits) != 1 {
		return false
	}
	for alias, value := range hosts {
		host, ok := value.(map[string]any)
		if !ok {
			return false
		}
		id, _ := host["ultra_exit_id"].(string)
		address, _ := host["ansible_host"].(string)
		if !regexp.MustCompile(`^[a-f0-9-]{36}$`).MatchString(id) || net.ParseIP(address) == nil ||
			alias != "exit_"+strings.ReplaceAll(
				id,
				"-",
				"",
			) || !regexp.MustCompile(`^exit_[a-f0-9]{32}$`).MatchString(alias) {
			return false
		}
		// Match freezeUpgradeExits exactly. These are isolated host variables,
		// including the baseline manifest optionally appended before drain.
		wanted := map[string]any{
			"ansible_host": address, "ansible_user": "root",
			"ansible_ssh_private_key_file": filepath.Join(directory, "identity"),
			"ansible_ssh_args":             "-F /dev/null -o ControlMaster=no -o ControlPath=none",
			"ansible_ssh_common_args": "-o BatchMode=yes -o UpdateHostKeys=no -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -o UserKnownHostsFile=" + shellQuote(
				filepath.Join(directory, alias+".pins"),
			),
			"ultra_exit_id": id,
		}
		if baseline, exists := host["ultra_host_previous_manifest"]; exists {
			if _, ok := baseline.(map[string]any); !ok {
				return false
			}
			wanted["ultra_host_previous_manifest"] = baseline
		}
		hostRaw, err := json.Marshal(host)
		if err != nil {
			return false
		}
		wantedRaw, err := json.Marshal(wanted)
		if err != nil || string(hostRaw) != string(wantedRaw) {
			return false
		}
	}
	expectedAll, _ := expected["all"].(map[string]any)
	expectedChildren, _ := expectedAll["children"].(map[string]any)
	initialExits, ok := expectedChildren["exits"]
	if !ok {
		return false
	}
	children["exits"] = initialExits
	normalizedRaw, err := json.Marshal(normalized)
	if err != nil {
		return false
	}
	expectedRaw, err := json.Marshal(expected)
	return err == nil && string(normalizedRaw) == string(expectedRaw)
}

// Any submitted applying stage without a success receipt may still be running
// remotely. Absence of current same-ID evidence must not enter the readiness wait.
func upgradeApplyingReservationPending(directory string) bool {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return true
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "lifecycle-applying-") {
			continue
		}
		stage := filepath.Join(directory, entry.Name())
		if _, err := os.Lstat(filepath.Join(stage, "job.json")); os.IsNotExist(err) {
			continue
		}
		raw, err := readBootstrapGenerationInput(filepath.Join(stage, "receipt.json"))
		var receipt deployansible.Receipt
		if err != nil || json.Unmarshal(raw, &receipt) != nil || receipt.State != "succeeded" {
			return true
		}
	}
	return false
}

// upgradeInventory excludes dedicated database hosts from the application
// runtime fleet. The database remains part of the frozen plan and request
// identity, but Ansible runtime probes and transitions target only VPN nodes.
func upgradeInventory(p *installplan.InstallPlan, directory string) (map[string]any, error) {
	clone := *p
	clone.Exits = nil
	clone.Database.Enabled = false
	return bootstrapInventory(&clone, directory)
}

// Continuation bypasses the normal cached activation/commit calls. Verify their
// exact frozen requests and private job/receipt bindings before skipping them.
func verifyCommittedUpgradeContinuation(directory string, inventory, variables map[string]any) error {
	generation, err := upgradeActivationGeneration(directory, false)
	if err != nil {
		return err
	}
	verify := func(stage, operation string, expectedVariables map[string]any) (deployansible.Receipt, error) {
		jobRaw, jobErr := readBootstrapGenerationInput(filepath.Join(stage, "job.json"))
		requestRaw, requestErr := readBootstrapGenerationInput(filepath.Join(stage, "request.json"))
		receiptRaw, receiptErr := readBootstrapGenerationInput(filepath.Join(stage, "receipt.json"))
		expected, marshalErr := expectedFrozenLocalRequest(requestRaw, inventory, expectedVariables)
		var job struct {
			Operation string `json:"operation"`
			Request   string `json:"request_sha256"`
			Binary    string `json:"binary_sha256"`
		}
		var receipt deployansible.Receipt
		if jobErr != nil || requestErr != nil || receiptErr != nil || marshalErr != nil || string(requestRaw) != string(expected) ||
			json.Unmarshal(jobRaw, &job) != nil ||
			json.Unmarshal(receiptRaw, &receipt) != nil ||
			job.Operation != operation ||
			job.Request != fmt.Sprintf("%x", sha256.Sum256(expected)) ||
			!runtimeHostValidDigest(job.Binary) ||
			receipt.RequestSHA256 != job.Request ||
			receipt.BinarySHA256 != job.Binary ||
			receipt.State != "succeeded" ||
			receipt.Result.Values["verified"] != true {
			return deployansible.Receipt{}, errors.New("upgrade_committed_continuation_receipt_invalid")
		}
		return receipt, nil
	}
	activation, err := verify(filepath.Join(directory, "activate"), "upgrade", variables)
	if err != nil {
		return err
	}
	timestamp, err := activationTimestamp(activation.Result.Values["activated_at"])
	if err != nil {
		return err
	}
	commitVariables := make(map[string]any, len(variables))
	for key, value := range variables {
		commitVariables[key] = value
	}
	commitVariables["ultra_upgrade_observed_at"] = timestamp
	_, err = verify(upgradeDependentStageDirectory(directory, "commit", generation), "commit-release", commitVariables)
	return err
}

func finishUpgradeCommit(
	ctx context.Context,
	p *installplan.InstallPlan,
	inspection upgradeInspection,
	inventory, variables map[string]any,
	directory, python, executable string,
	domainTransaction *upgradeDomainTransaction,
	resume func(context.Context) error,
	generation int,
	retryFailed bool,
	version string,
) error {
	var err error
	// Old endpoints are retired only after the release commit succeeded. These
	// durable phases retry the same generation; failures preserve the gate.
	if domainTransaction.DNSChanged {
		for _, phase := range []string{"promote", "retire", "retire-dns", "finalize"} {
			if err = domainTransaction.phase(ctx, inventory, directory, python, executable, phase, generation); err != nil {
				return errors.New("upgrade_domain_post_commit_retirement_incomplete")
			}
		}
	} else if domainTransaction.Changed {
		if err = domainTransaction.phase(ctx, inventory, directory, python, executable, "finalize", generation); err != nil {
			return errors.New("upgrade_domain_metadata_finalize_incomplete")
		}
	}
	if err = runUpgradeRuntimeEffectsCommit(ctx, p, inspection, inventory, variables, directory, python, executable, generation); err != nil {
		// The release and endpoint cutover have committed. Keep the lifecycle gate
		// held so this exact effect receipt can be safely retried.
		return errors.New("upgrade_runtime_effect_commit_incomplete")
	}
	if err == nil && retryFailed {
		err = clearRetriedVersionMarker(ctx, inspection.AutoPolicy, directory, version)
	}
	if err != nil {
		return err
	}
	// Restore schedules while the active reservation still protects this commit.
	// Completion-only recovery must never claim this cleanup happened implicitly.
	if err = resume(ctx); err != nil {
		return errors.New("upgrade_automation_resume_failed")
	}
	if err = saveEnforcementReleaseIntent(directory, inventory, variables, inspection.ObservedAt); err != nil {
		return err
	}
	return ansibleLifecycle(ctx, p, inventory, directory, python, executable, "released", false)
}

// Failed read-only inspections get a new immutable job on the next invocation.
// Successful and interrupted jobs retain their original cache/resume semantics.
// The caller holds the fleet lease; activation and other mutations never use this.
func runUpgradeInspection(
	ctx context.Context,
	operation string,
	inventory, variables map[string]any,
	directory, python, executable string,
) (deployansible.Receipt, error) {
	if operation != "inspect-upgrade" && operation != "inspect-release-hosts" && operation != "inspect-upgrade-runtime" &&
		operation != "inspect-upgrade-domains" {
		return deployansible.Receipt{}, errors.New("upgrade_inspection_operation_required")
	}
	for attempt := 1; attempt <= 1000; attempt++ {
		stage := directory
		if attempt > 1 {
			stage = fmt.Sprintf("%s-attempt-%d", directory, attempt)
		}
		raw, err := readBootstrapGenerationInput(filepath.Join(stage, "receipt.json"))
		if os.IsNotExist(err) {
			return deployansible.RunLocal(ctx, operation, inventory, variables, stage, python, executable)
		}
		var receipt deployansible.Receipt
		if err != nil || json.Unmarshal(raw, &receipt) != nil {
			return deployansible.Receipt{}, errors.New("upgrade_inspection_receipt_invalid")
		}
		if receipt.State != "failed" {
			return deployansible.RunLocal(ctx, operation, inventory, variables, stage, python, executable)
		}
		jobRaw, jobErr := readBootstrapGenerationInput(filepath.Join(stage, "job.json"))
		requestRaw, requestErr := readBootstrapGenerationInput(filepath.Join(stage, "request.json"))
		request, expectedErr := deployansible.LocalRequestBytes(ctx, operation, stage, inventory, variables)
		hash := fmt.Sprintf("%x", sha256.Sum256(request))
		var job struct {
			Operation string `json:"operation"`
			Request   string `json:"request_sha256"`
			Binary    string `json:"binary_sha256"`
		}
		if jobErr != nil || requestErr != nil || expectedErr != nil || json.Unmarshal(jobRaw, &job) != nil ||
			string(requestRaw) != string(request) ||
			job.Operation != operation ||
			job.Request != hash ||
			receipt.RequestSHA256 != hash ||
			job.Binary == "" ||
			receipt.BinarySHA256 != job.Binary {
			return deployansible.Receipt{}, errors.New("upgrade_inspection_inputs_changed")
		}
	}
	return deployansible.Receipt{}, errors.New("upgrade_inspection_attempt_limit")
}

func writeUpgradeInput(path string, data []byte) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("upgrade_input_not_private")
		}
		previous, err := os.ReadFile(path)
		if err != nil || string(previous) != string(data) {
			return errors.New("upgrade_immutable_input_changed")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".immutable-input-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name) //nolint:errcheck
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	// Publish without overwriting another immutable input; failed writes never
	// leave a partial final path that could poison resume after a crash.
	if err = os.Link(name, path); err != nil {
		return err
	}
	if err = os.Remove(name); err != nil {
		return err
	}
	return syncUpgradeDirectory(filepath.Dir(path))
}

func compatibleAnsibleRelease(previous, target *automationRelease) error {
	required := []string{"service-access-v1", "provider-pool-quota-v1"}
	for _, capability := range required {
		has := func(manifest *automationRelease) bool {
			for _, value := range manifest.Capabilities {
				if value == capability {
					return true
				}
			}
			return false
		}
		if !has(previous) || !has(target) {
			return fmt.Errorf("upgrade_compatible_%s_required", capability)
		}
	}
	if target.DatabaseSchemaMin <= 0 || target.DatabaseSchemaMax < target.DatabaseSchemaMin ||
		previous.DatabaseSchemaMin > target.DatabaseSchemaMin ||
		previous.DatabaseSchemaMax < target.DatabaseSchemaMax {
		return errors.New("upgrade_compatible_schema_required")
	}
	return nil
}

func activationTimestamp(value any) (int64, error) {
	switch value := value.(type) {
	case float64:
		if value <= 0 || value > 9007199254740991 || value != float64(int64(value)) {
			return 0, errors.New("invalid_activation_timestamp")
		}
		return int64(value), nil
	case string:
		return strconv.ParseInt(value, 10, 64)
	default:
		return 0, errors.New("invalid_activation_timestamp")
	}
}

func freezeUpgradeExits(inspection upgradeInspection, directory string) (map[string]any, error) {
	if inspection.ObservedAt <= 0 || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(inspection.TopologySHA) ||
		len(inspection.Nodes) == 0 ||
		len(inspection.Nodes) > 16 ||
		inspection.Identity == "" {
		return nil, errors.New("upgrade_topology_invalid")
	}
	identityPath := filepath.Join(directory, "identity")
	if err := writeUpgradeInput(identityPath, []byte(inspection.Identity)); err != nil {
		return nil, err
	}
	nodes := map[string]any{}
	for _, node := range inspection.Nodes {
		if !regexp.MustCompile(`^[a-f0-9-]{36}$`).MatchString(node.ID) || net.ParseIP(node.Address) == nil || node.Pins == "" {
			return nil, errors.New("upgrade_node_invalid")
		}
		alias := "exit_" + strings.ReplaceAll(node.ID, "-", "")
		if _, found := nodes[alias]; found {
			return nil, errors.New("upgrade_duplicate_node")
		}
		pins := filepath.Join(directory, alias+".pins")
		if err := writeUpgradeInput(pins, []byte(node.Pins)); err != nil {
			return nil, err
		}
		nodes[alias] = map[string]any{
			"ansible_host":                 node.Address,
			"ansible_user":                 "root",
			"ansible_ssh_private_key_file": identityPath,
			"ansible_ssh_args":             "-F /dev/null -o ControlMaster=no -o ControlPath=none",
			"ansible_ssh_common_args": "-o BatchMode=yes -o UpdateHostKeys=no -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -o UserKnownHostsFile=" + shellQuote(
				pins,
			),
			"ultra_exit_id": node.ID,
		}
	}
	return nodes, nil
}
