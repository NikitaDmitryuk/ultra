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
	DatabaseSchema      int               `json:"database_schema"`
	ControllerDirectory string            `json:"controller_directory"`
	ControllerUnitSHA   string            `json:"controller_unit_sha256"`
	ToolHashes          map[string]string `json:"tool_hashes"`
	AutoPolicy          map[string]any    `json:"auto_policy"`
	ObservedAt          int64             `json:"observed_at"`
	Architecture        string            `json:"architecture"`
	TopologySHA         string            `json:"topology_sha256"`
	Identity            string            `json:"identity"`
	PreviousManifestSHA string            `json:"previous_manifest_sha256"`
	Previous            automationRelease `json:"previous_manifest"`
	Nodes               []struct {
		ID      string `json:"id"`
		Address string `json:"address"`
		Pins    string `json:"pins"`
	} `json:"nodes"`
}

// Upgrade retains a frozen private job directory across process/SSH failures.
// It never falls back to the former SSH installer after an Ansible error.
func ansibleUpgrade(ctx context.Context, p *installplan.InstallPlan, releaseDir, directory, python, executable string, retryFailed bool) (returnErr error) {
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
	ctx, releaseLock, err := withFrozenLifecycleLock(operatorCtx, p, lockDirectory, directory)
	if err != nil {
		return err
	}
	lockHeld := true
	defer func() {
		if lockHeld {
			releaseLock()
		}
	}()
	clone := *p
	clone.Exits = nil
	inventory, err := bootstrapInventory(&clone, directory)
	if err != nil {
		return err
	}
	if err = ansibleLifecycle(ctx, p, inventory, directory, python, executable, "applying", true); err != nil {
		return err
	}
	inspectionReceipt, err := deployansible.RunLocal(ctx, "inspect-upgrade", inventory, map[string]any{"ultra_lock_directory": lockDirectory}, filepath.Join(directory, "inspect"), python, executable)
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
	if err = compatibleAnsibleRelease(&inspection.Previous, manifest); err != nil {
		return err
	}
	if inspection.DatabaseSchema < manifest.DatabaseSchemaMin || inspection.DatabaseSchema > manifest.DatabaseSchemaMax {
		return errors.New("upgrade_database_schema_incompatible")
	}
	if inspection.Architecture != "amd64" && inspection.Architecture != "arm64" {
		return errors.New("upgrade_architecture_invalid")
	}
	if inspection.ObservedAt <= 0 || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(inspection.TopologySHA) || len(inspection.Nodes) == 0 || len(inspection.Nodes) > 16 || inspection.Identity == "" {
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
	_, err = deployansible.RunLocal(ctx, "inspect-release-hosts", inventory, map[string]any{"ultra_lock_directory": lockDirectory, "ultra_release_inspection_directory": inspectionDirectory}, filepath.Join(directory, "hosts"), python, executable)
	if err != nil {
		return err
	}
	bridge := children["bridge"].(map[string]any)["hosts"].(map[string]any)["bridge"].(map[string]any)
	bridge["ultra_architecture"] = inspection.Architecture
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
	tools, err := extractUpgradeTools(filepath.Join(releaseDir, "ultra-recovery.tar.gz"), filepath.Join(directory, "recovery-bundle"), inspection.ToolHashes)
	if err != nil {
		return err
	}
	bridge["ultra_recovery_files"] = tools
	for alias, value := range nodes {
		node := value.(map[string]any)
		arch := node["ultra_architecture"].(string)
		selected := []map[string]any{}
		for _, tool := range tools {
			base := filepath.Base(tool["destination"].(string))
			if base == "recovery.py" || base == "monitor.py" || base == "heartbeat.py" || strings.HasPrefix(base, "ultra-monitor") || strings.HasPrefix(base, "ultra-recovery-prune") {
				selected = append(selected, tool)
			}
		}
		client, err := upgradeClientTool(manifest, &inspection.Previous, releaseDir, arch)
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
	controllerRendered := strings.ReplaceAll(string(controllerUnit), "{{ ultra_controller_directory }}", bridge["ultra_controller_directory"].(string))
	controllerHash := sha256.Sum256([]byte(controllerRendered))
	bridge["ultra_previous_controller_directory"] = inspection.ControllerDirectory
	bridge["ultra_previous_controller_unit_sha256"] = inspection.ControllerUnitSHA
	bridge["ultra_target_controller_unit_sha256"] = hex.EncodeToString(controllerHash[:])
	bridge["ultra_auto_upgrade_policy"] = inspection.AutoPolicy
	bridge["ultra_auto_upgrade_enabled"] = inspection.AutoPolicy["enabled"] == true
	manifestSHA, err := sourceSHA(filepath.Join(releaseDir, "release-manifest.json"))
	if err != nil {
		return err
	}
	variables := map[string]any{"ultra_lock_directory": lockDirectory, "ultra_upgrade_observed_at": inspection.ObservedAt, "ultra_release_manifest": manifest, "ultra_release_manifest_sha256": manifestSHA, "ultra_previous_manifest_sha256": inspection.PreviousManifestSHA, "ultra_previous_manifest": inspection.Previous, "ultra_release_source": releaseDir, "ultra_release_version": manifest.Version, "ultra_topology_sha256": inspection.TopologySHA, "ultra_bridge_inventory_host": "bridge", "ultra_release_probe_executable": "/var/lib/ultra-ansible/releases/" + manifest.Version + "/ultra-install"}
	frozenInventory, err := json.Marshal(inventory)
	if err != nil {
		return err
	}
	if err = writeUpgradeInput(filepath.Join(directory, "inventory.frozen.json"), frozenInventory); err != nil {
		return err
	}
	if retryFailed {
		preflightDirectory, err := os.MkdirTemp(directory, "retry-preflight-")
		if err != nil {
			return err
		}
		_ = os.Remove(preflightDirectory)
		if _, err = deployansible.RunLocal(ctx, "preflight-retry", inventory, variables, preflightDirectory, python, executable); err != nil {
			return err
		}
		if err = resetFailedUpgradeAttempt(directory); err != nil {
			return err
		}
	}
	// A separate attempt always resumes timers, including after UNREACHABLE.
	resume := func(cleanup context.Context) error {
		resumeDirectory, err := os.MkdirTemp(directory, "resume-")
		if err == nil {
			_ = os.Remove(resumeDirectory)
			_, err = deployansible.RunLocal(cleanup, "resume-automation", inventory, map[string]any{"ultra_lock_directory": lockDirectory}, resumeDirectory, python, executable)
		}
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
		if err := resume(cleanup); err != nil {
			returnErr = errors.Join(returnErr, errors.New("upgrade_automation_resume_failed"))
		}
		if returnErr == nil {
			returnErr = sealCompletedOperatorOperation(directory, "upgrade", manifest, manifestSHA)
			if returnErr == nil {
				returnErr = collectCompletedOperatorArtifacts(filepath.Dir(directory), manifest, &inspection.Previous)
			}
		}
	}()
	generation, err := upgradeActivationGeneration(directory, false)
	if err != nil {
		return err
	}
	activation, activationErr := deployansible.RunLocal(ctx, "upgrade", inventory, variables, filepath.Join(directory, "activate"), python, executable)
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
		_, err = deployansible.RunLocal(ctx, "publish-release", inventory, variables, upgradeDependentStageDirectory(directory, "publish", generation), python, executable)
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
			deadline := time.Now().Add(6 * time.Minute)
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
	if err != nil {
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
		_, rollbackErr := deployansible.RunLocal(cleanup, "rollback", inventory, variables, upgradeDependentStageDirectory(directory, "rollback", generation), python, executable)
		if rollbackErr != nil {
			return errors.Join(err, errors.New("upgrade_compatible_rollback_incomplete"))
		}
		if gateErr := ansibleLifecycle(cleanup, p, inventory, directory, python, executable, "released", false); gateErr != nil {
			return errors.Join(err, gateErr)
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
	_, err = deployansible.RunLocal(ctx, "commit-release", inventory, variables, upgradeDependentStageDirectory(directory, "commit", generation), python, executable)
	if err == nil && retryFailed {
		err = clearRetriedVersionMarker(ctx, inspection.AutoPolicy, directory, manifest.Version)
	}
	if err == nil {
		err = ansibleLifecycle(ctx, p, inventory, directory, python, executable, "released", false)
	}
	return err
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
	if target.DatabaseSchemaMin <= 0 || target.DatabaseSchemaMax < target.DatabaseSchemaMin || previous.DatabaseSchemaMin > target.DatabaseSchemaMin || previous.DatabaseSchemaMax < target.DatabaseSchemaMax {
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
	if inspection.ObservedAt <= 0 || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(inspection.TopologySHA) || len(inspection.Nodes) == 0 || len(inspection.Nodes) > 16 || inspection.Identity == "" {
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
		nodes[alias] = map[string]any{"ansible_host": node.Address, "ansible_user": "root", "ansible_ssh_private_key_file": identityPath, "ansible_ssh_args": "-F /dev/null -o ControlMaster=no -o ControlPath=none", "ansible_ssh_common_args": "-o BatchMode=yes -o UpdateHostKeys=no -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -o UserKnownHostsFile=" + shellQuote(pins), "ultra_exit_id": node.ID}
	}
	return nodes, nil
}
