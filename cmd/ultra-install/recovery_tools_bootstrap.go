package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// This deliberately separate operator command repairs recovery executables only.
// It does not waive readiness, change the installed manifest, or activate a relay.
func runRecoveryToolsBootstrapCommand(args []string) {
	fs := flag.NewFlagSet("ultra-install recovery-tools-bootstrap", flag.ExitOnError)
	config := fs.String("config", "install.config", "canonical deployment configuration")
	release := fs.String("release-dir", "", "verified local candidate release")
	version := fs.String("version", "", "exact candidate version")
	manifestSHA := fs.String("candidate-sha256", "", "exact candidate release-manifest SHA256")
	directory := fs.String(
		"job-dir",
		"/var/lib/ultra-ansible/recovery-tools-bootstrap-operation",
		"durable operation directory; retain across candidate rebuilds",
	)
	python := fs.String("python", "/usr/bin/python3", "controller Python")
	executable := fs.String("ansible-playbook", "", "pinned candidate Ansible executable")
	retry := fs.Bool("retry-failed", false, "explicitly resume the same failed frozen repair phases")
	manualExcluded := fs.Bool(
		"manual-consumers-excluded",
		false,
		"operator excludes manual root recovery/restore/import commands until completion",
	)
	_ = fs.Parse(args)
	if fs.NArg() != 0 || !*manualExcluded || *release == "" || *version == "" ||
		!regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(*manifestSHA) {
		exitOnErr("recovery bootstrap", errors.New("bootstrap_exact_candidate_and_manual_exclusion_required"))
		return
	}
	p := readLifecycleDeploymentOrExit("", *config)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	exitOnErr(
		"recovery bootstrap",
		recoveryToolsBootstrap(ctx, p, *release, *version, *manifestSHA, *directory, *python, *executable, *retry),
	)
}

func recoveryBootstrapSelection(tools []map[string]any, bridge bool, generation, version string) ([]map[string]any, error) {
	wanted := map[string]bool{"recovery.py": true}
	if bridge {
		wanted["restore_host.py"], wanted["restore_database.py"] = true, true
	}
	selected := make([]map[string]any, 0)
	for _, original := range tools {
		name := filepath.Base(original["destination"].(string))
		if !wanted[name] {
			continue
		}
		old, ok := original["previous_sha256"].(string)
		if !ok || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(old) {
			return nil, errors.New("bootstrap_old_generation_incomplete")
		}
		tool := make(map[string]any)
		for key, value := range original {
			tool[key] = value
		}
		tool["baseline_controller_source"] = filepath.Join(generation, name)
		tool["baseline_source"] = filepath.Join("/var/lib/ultra-ansible/releases", version, "bootstrap-baseline", name)
		selected = append(selected, tool)
		delete(wanted, name)
	}
	if len(wanted) != 0 {
		return nil, errors.New("bootstrap_candidate_tools_incomplete")
	}
	return selected, nil
}

func recoveryBootstrapStablePlan(p *installplan.InstallPlan) *installplan.InstallPlan {
	stable := *p
	if p.Automation != nil {
		automation := *p.Automation
		automation.Version, automation.ReleaseDir = "", ""
		stable.Automation = &automation
	}
	return &stable
}

func recoveryBootstrapDistinctGeneration(version string, installed []byte) error {
	var previous automationRelease
	if json.Unmarshal(installed, &previous) != nil || !validAutomationVersion(previous.Version) {
		return errors.New("bootstrap_installed_manifest_invalid")
	}
	if previous.Version == version {
		return errors.New("bootstrap_installed_generation_is_immutable")
	}
	return nil
}

func runRecoveryBootstrapStage(
	ctx context.Context,
	retry bool,
	operation string,
	inventory, variables map[string]any,
	stage, python, executable string,
) (deployansible.Receipt, error) {
	if retry {
		return deployansible.RunLocalRetryFailed(ctx, operation, inventory, variables, stage, python, executable)
	}
	return deployansible.RunLocal(ctx, operation, inventory, variables, stage, python, executable)
}

func recoveryToolsBootstrap(
	ctx context.Context,
	p *installplan.InstallPlan,
	release, version, expectedSHA, directory, python, executable string,
	retry bool,
) error {
	if err := installplan.ValidatePlan(p); err != nil {
		return err
	}
	if os.Geteuid() != 0 || !localLifecycleBridge(p) {
		return errors.New("bootstrap_must_execute_on_attested_bridge")
	}
	var err error
	release, err = filepath.Abs(release)
	if err != nil {
		return err
	}
	// The explicit SHA is the trusted manual-build handoff, as in the normal
	// operator path. Verify every asset against that exact manifest; local
	// manual bundles do not acquire fabricated release signatures.
	manifest, err := verifyAutomationRelease(release, version)
	if err != nil {
		return err
	}
	actualSHA, err := sourceSHA(filepath.Join(release, "release-manifest.json"))
	if err != nil || actualSHA != expectedSHA || manifest.Version != version {
		return errors.New("bootstrap_candidate_identity_mismatch")
	}
	installed, err := readBootstrapGenerationInput("/opt/ultra-recovery/release-manifest.json")
	if err != nil {
		return err
	}
	if err = recoveryBootstrapDistinctGeneration(version, installed); err != nil {
		return err
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		return err
	}
	if err = ensurePrivateBootstrapDirectory(directory); err != nil {
		return err
	}
	// Stable operation identity is independent of a later candidate rebuild.
	if err = freezeOperatorPlan(directory, recoveryBootstrapStablePlan(p), ""); err != nil {
		return err
	}
	stateRoot := "/var/lib/ultra-ansible"
	ctx, releaseOperator, err := withBootstrapOperatorLock(ctx, stateRoot)
	if err != nil {
		return err
	}
	defer releaseOperator()
	lock, err := freezeBootstrapExecution(p, directory, stateRoot)
	if err != nil {
		return err
	}
	runtimePlan := *p
	if p.Automation != nil {
		automation := *p.Automation
		automation.ReleaseDir, automation.Version = release, version
		runtimePlan.Automation = &automation
	}
	executable, err = resolveAnsibleRuntime(ctx, &runtimePlan, lock, executable)
	if err != nil {
		return err
	}
	targetDirectory := filepath.Join(directory, "candidates", expectedSHA)
	if err = ensurePrivateBootstrapDirectory(targetDirectory); err != nil {
		return err
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return err
	}
	if err = pinOperatorRelease(filepath.Join(cache, "ultra", "releases"), targetDirectory, release); err != nil {
		return err
	}
	closeRuntime, err := pinOperatorRuntimeForOperation(targetDirectory, executable)
	if err != nil {
		return err
	}
	defer closeRuntime()
	ctx, releaseLifecycle, err := withFrozenLifecycleLock(ctx, p, lock, directory)
	if err != nil {
		return err
	}
	defer releaseLifecycle()
	inv, err := upgradeInventory(p, directory)
	if err != nil {
		return err
	}
	if _, err = ansibleLifecycleReserve(ctx, p, inv, directory, python, executable, "applying"); err != nil {
		return err
	}
	run := func(operation string, inventory, variables map[string]any, stage string) (deployansible.Receipt, error) {
		return runRecoveryBootstrapStage(ctx, retry, operation, inventory, variables, stage, python, executable)
	}
	inspection, err := run(
		"bootstrap-recovery-inspect",
		inv,
		map[string]any{"ultra_lock_directory": lock},
		filepath.Join(directory, "inventory"),
	)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(inspection.Result.Values)
	if err != nil {
		return err
	}
	var observed struct {
		upgradeInspection
		Generation string `json:"generation"`
	}
	if json.Unmarshal(raw, &observed) != nil ||
		observed.Generation != filepath.Join("/opt/ultra-recovery/releases", observed.Previous.Version) {
		return errors.New("bootstrap_inventory_invalid")
	}
	exits, err := freezeUpgradeExits(observed.upgradeInspection, directory)
	if err != nil {
		return err
	}
	tools, err := extractUpgradeTools(
		filepath.Join(release, "ultra-recovery.tar.gz"),
		filepath.Join(targetDirectory, "tools"),
		observed.ToolHashes,
	)
	if err != nil {
		return err
	}
	bridgeTools, err := recoveryBootstrapSelection(tools, true, observed.Generation, version)
	if err != nil {
		return err
	}
	exitTools, err := recoveryBootstrapSelection(tools, false, observed.Generation, version)
	if err != nil {
		return err
	}
	children := inv["all"].(map[string]any)["children"].(map[string]any)
	children["bridge"].(map[string]any)["hosts"].(map[string]any)["bridge"].(map[string]any)["ultra_recovery_files"] = bridgeTools
	for _, node := range exits {
		node.(map[string]any)["ultra_recovery_files"] = exitTools
	}
	children["exits"] = map[string]any{"hosts": exits}
	variables := map[string]any{"ultra_lock_directory": lock, "ultra_release_version": version,
		"ultra_recovery_bootstrap_baseline":  observed.PreviousManifestSHA,
		"ultra_recovery_bootstrap_topology":  observed.TopologySHA,
		"ultra_recovery_bootstrap_candidate": expectedSHA}
	// All hosts finish each phase before the first host enters the next one.
	// Any error retains durable fences and lifecycle ownership for explicit retry.
	for _, phase := range []string{"fence", "seed", "apply", "verify", "resume"} {
		variables["ultra_recovery_bootstrap_phase"] = phase
		receipt, phaseErr := run("bootstrap-recovery-tools", inv, variables, filepath.Join(targetDirectory, phase))
		if phaseErr != nil {
			return fmt.Errorf("bootstrap_%s_failed; durable fences retained: %w", phase, phaseErr)
		}
		if receipt.Result.Values["verified"] != true {
			return errors.New("bootstrap_phase_unverified")
		}
	}
	// A completed cached phase is historical evidence. Recheck actual tools,
	// exact retained fallbacks and restored schedules on every invocation.
	proofDirectory, err := os.MkdirTemp(targetDirectory, "completion-proof-")
	if err != nil {
		return err
	}
	if err = os.Remove(proofDirectory); err != nil {
		return err
	}
	variables["ultra_recovery_bootstrap_phase"] = "proof"
	proof, err := deployansible.RunLocal(ctx, "bootstrap-recovery-tools", inv, variables, proofDirectory, python, executable)
	if err != nil {
		return err
	}
	if proof.Result.Values["verified"] != true {
		return errors.New("bootstrap_completion_unverified")
	}
	if err = ansibleLifecycle(ctx, p, inv, directory, python, executable, "released", false); err != nil {
		return err
	}
	fmt.Println("recovery tools repaired; fresh backup, independent reconciliation and normal upgrade readiness are still required")
	return nil
}
