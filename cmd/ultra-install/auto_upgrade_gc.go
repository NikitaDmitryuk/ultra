package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

// Publication and pending identity share the fleet lease with collection. A
// collector cannot remove a newly published download before handoff pins it.
func prepareAutoReleaseWithRetention(ctx context.Context, client *http.Client, policy autoUpgradePolicy, releaseInfo githubStableRelease) (string, error) {
	ctx, release, err := deployansible.WithOperationLock(ctx, policy.OperationLockDirectory)
	if err != nil {
		return "", err
	}
	defer release()
	directory, err := os.MkdirTemp(policy.OperationLockDirectory, "retain-source-")
	if err != nil {
		return "", err
	}
	policyPath := filepath.Join(directory, "policy.json")
	raw, err := json.Marshal(policy)
	if err != nil {
		return "", err
	}
	if err = writeUpgradeInput(policyPath, raw); err != nil {
		return "", err
	}
	executable := policy.Ansible
	if executable == "" {
		executable = "/opt/ultra-ansible/current/venv/bin/ansible-playbook"
	}
	inventory := map[string]any{"all": map[string]any{"children": map[string]any{
		"bridge": map[string]any{"hosts": map[string]any{"bridge": map[string]any{"ansible_connection": "local"}}},
	}}}
	variables := map[string]any{"ultra_lock_directory": policy.OperationLockDirectory, "ultra_retention_auto_policy": policyPath}
	if _, err = deployansible.RunLocal(ctx, "retain-artifacts", inventory, variables, filepath.Join(directory, "collect"), policy.Python, executable); err != nil {
		return "", err
	}
	target, err := prepareAutoRelease(ctx, client, policy, releaseInfo)
	if err != nil {
		return "", err
	}
	identity, err := targetChannelIdentity(target, releaseInfo.Tag)
	if err != nil {
		return "", err
	}
	if err = updateChannelState(policy, identity, "pending"); err != nil {
		return "", err
	}
	return target, nil
}

func autoUpgradeCommitDirectory(directory string) (string, error) {
	generation, err := upgradeActivationGeneration(directory, false)
	if err != nil {
		return "", err
	}
	return upgradeDependentStageDirectory(directory, "commit", generation), nil
}
