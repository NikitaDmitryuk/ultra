package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func ansibleAutomationStatus(ctx context.Context, p *installplan.InstallPlan, python, executable string) error {
	if err := installplan.ValidatePlan(p); err != nil {
		return err
	}
	directory, err := os.MkdirTemp("", "ultra-ansible-status-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory) //nolint:errcheck
	if executable == "" {
		installed := "/opt/ultra-ansible/current/venv/bin/ansible-playbook"
		if info, statErr := os.Stat(installed); statErr == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			executable = installed
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
	clone := *p
	clone.Exits = nil
	inventory, err := bootstrapInventory(&clone, directory)
	if err != nil {
		return err
	}
	receipt, err := deployansible.RunLocal(ctx, "status-automation", inventory, map[string]any{}, filepath.Join(directory, "status"), python, executable)
	if err != nil {
		return errors.New("automation_status_unavailable")
	}
	raw, err := json.Marshal(publicAutomationStatus(receipt.Result.Values))
	if err != nil {
		return err
	}
	fmt.Println(string(raw))
	if receipt.Result.Values["ready"] != true {
		return errors.New("automation_not_ready")
	}
	return nil
}

func publicAutomationStatus(values map[string]any) map[string]any {
	result := map[string]any{}
	for _, key := range []string{"ready", "independent", "version", "backup_age_seconds", "controller_age_seconds", "reasons"} {
		if value, ok := values[key]; ok {
			result[key] = value
		}
	}
	return result
}
