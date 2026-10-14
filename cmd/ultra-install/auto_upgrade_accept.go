package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func runAutoUpgradeAcceptCommand(args []string) {
	flags := flag.NewFlagSet("enable-auto-upgrade", flag.ExitOnError)
	config := flags.String("config", "", "canonical deployment configuration")
	confirm := flags.String("confirm", "", "ACCEPT after verified production rollout")
	python := flags.String("python", "/usr/bin/python3", "operator Python")
	ansible := flags.String("ansible-playbook", "", "trusted installed or exact pinned runtime")
	_ = flags.Parse(args)
	if *confirm != "ACCEPT" {
		exitOnErr("stable channel acceptance", errors.New("explicit_production_acceptance_required"))
		return
	}
	p, err := installplan.LoadConfig(*config)
	if err != nil {
		exitOnErr("stable channel acceptance", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	exitOnErr("stable channel acceptance", enableAutoUpgrade(ctx, p, *python, *ansible))
}
func enableAutoUpgrade(ctx context.Context, p *installplan.InstallPlan, python, executable string) (returnErr error) {
	if err := installplan.ValidatePlan(p); err != nil {
		return err
	}
	stateRoot, err := bootstrapStateRoot()
	if err != nil {
		return err
	}
	operatorCtx, releaseOperator, err := withBootstrapOperatorLock(ctx, stateRoot)
	if err != nil {
		return err
	}
	defer releaseOperator()
	attemptRoot := filepath.Join(stateRoot, "enable-auto-upgrade")
	if err = ensurePrivateBootstrapDirectory(attemptRoot); err != nil {
		return err
	}
	directory, err := beginBootstrapAttempt(attemptRoot)
	if err != nil {
		return err
	}
	lockRoot, err := freezeBootstrapExecution(p, directory, stateRoot)
	if err != nil {
		return err
	}
	// Read-only installed runtime selection does not depend on a stale source release path.
	if executable == "" {
		path := "/opt/ultra-ansible/current/venv/bin/ansible-playbook"
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			executable = path
		}
	}
	executable, err = resolveAnsibleRuntime(ctx, p, directory, executable)
	if err != nil {
		return err
	}
	runtimeRelease, err := pinOperatorRuntimeForOperation(directory, executable)
	if err != nil {
		return err
	}
	defer runtimeRelease()
	ctx, release, err := withFrozenLifecycleLock(operatorCtx, p, lockRoot, directory)
	if err != nil {
		return err
	}
	defer release()
	clone := *p
	clone.Exits = nil
	inventory, err := bootstrapInventory(&clone, directory)
	if err != nil {
		return err
	}
	err = withAutoAcceptanceGate(ctx, func(gateCtx context.Context, phase string, drain bool) error {
		return ansibleLifecycle(gateCtx, p, inventory, directory, python, executable, phase, drain)
	}, func() error {
		receipt, err := deployansible.RunLocal(ctx, "inspect-upgrade", inventory, map[string]any{"ultra_lock_directory": lockRoot}, filepath.Join(directory, "inspect"), python, executable)
		if err != nil {
			return err
		}
		raw, _ := json.Marshal(receipt.Result.Values)
		var inspection upgradeInspection
		if json.Unmarshal(raw, &inspection) != nil {
			return errors.New("auto_accept_inspection_invalid")
		}
		repository, ok := inspection.AutoPolicy["repository"].(string)
		if !ok {
			return errors.New("auto_accept_signed_policy_required")
		}
		var checks []string
		if names, ok := inspection.AutoPolicy["required_checks"].([]any); ok {
			for _, name := range names {
				value, ok := name.(string)
				if !ok {
					return errors.New("auto_accept_ci_policy_invalid")
				}
				checks = append(checks, value)
			}
		}
		if len(checks) == 0 {
			return errors.New("auto_accept_ci_policy_invalid")
		}
		if err = verifyGithubCI(ctx, &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 60 * time.Second}, repository, inspection.Previous.Version, inspection.Previous.SourceCommit, checks); err != nil {
			return err
		}
		nodes, err := freezeUpgradeExits(inspection, directory)
		if err != nil {
			return err
		}
		inventory["all"].(map[string]any)["children"].(map[string]any)["exits"] = map[string]any{"hosts": nodes}
		vars := map[string]any{"ultra_lock_directory": lockRoot, "ultra_release_version": inspection.Previous.Version, "ultra_accepted_manifest": inspection.Previous, "ultra_accept_observed_at": inspection.ObservedAt}
		_, err = deployansible.RunLocal(ctx, "enable-auto-upgrade", inventory, vars, filepath.Join(directory, "accept"), python, executable)
		return err
	})
	if err != nil {
		return err
	}
	return completeBootstrapAttempt(attemptRoot, directory)
}

// Register cleanup before reservation/drain: reservation may commit successfully
// while its subsequent drain fails or its response is lost.
func withAutoAcceptanceGate(ctx context.Context, lifecycle func(context.Context, string, bool) error, action func() error) (returnErr error) {
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		if err := lifecycle(cleanup, "released", false); err != nil {
			returnErr = errors.Join(returnErr, err)
		}
	}()
	if err := lifecycle(ctx, "applying", true); err != nil {
		return err
	}
	return action()
}
