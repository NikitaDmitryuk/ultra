package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func statusPlanWithRelease(p *installplan.InstallPlan, directory string) (*installplan.InstallPlan, error) {
	if directory == "" {
		return p, nil
	}
	if p.Automation == nil {
		return nil, errors.New("status_release_requires_automation")
	}
	if _, err := verifyAutomationRelease(directory, p.Automation.Version); err != nil {
		return nil, err
	}
	copyPlan, automation := *p, *p.Automation
	automation.ReleaseDir = directory
	copyPlan.Automation = &automation
	return &copyPlan, nil
}

func ansibleAutomationStatus(ctx context.Context, p *installplan.InstallPlan, python, executable string, showDetails bool) error {
	return retryAutomationStatus(ctx, func(ctx context.Context) error {
		return ansibleAutomationStatusAttempt(ctx, p, python, executable, showDetails)
	})
}

func retryAutomationStatus(ctx context.Context, attemptFunc func(context.Context) error) error {
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		last = attemptFunc(ctx)
		if err := ctx.Err(); err != nil {
			return err
		}
		if last == nil || !transientAutomationStatusFailure(last) || attempt == 2 {
			return last
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return last
}

func ansibleAutomationStatusAttempt(ctx context.Context, p *installplan.InstallPlan, python, executable string, showDetails bool) error {
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
	receipt, err := deployansible.RunLocal(
		ctx,
		"status-automation",
		inventory,
		map[string]any{},
		filepath.Join(directory, "status"),
		python,
		executable,
	)
	if err != nil {
		return automationStatusFailure(receipt.Diagnostic)
	}
	raw, err := json.Marshal(publicAutomationStatus(receipt.Result.Values))
	if err != nil {
		return err
	}
	if showDetails {
		fmt.Println(string(raw))
	}
	if receipt.Result.Values["ready"] != true {
		return errors.New("automation_not_ready")
	}
	return nil
}

func transientAutomationStatusFailure(err error) bool {
	if err == nil {
		return false
	}
	switch err.Error() {
	case "automation_status_unavailable (ssh_banner_timeout)",
		"automation_status_unavailable (ssh_connect_timeout)",
		"automation_status_unavailable (ssh_connection_reset)":
		return true
	default:
		return false
	}
}

func automationStatusFailure(diagnostic deployansible.Diagnostic) error {
	// The fixed status playbook can fail a task or SSH connection. Only publish
	// these callback classifications; receipt fields and executor errors may
	// otherwise contain private host data or arbitrary module output.
	switch diagnostic.Code {
	case "task_failed", "host_unreachable", "ssh_connection_refused", "ssh_authentication_failed",
		"ssh_control_path_too_long", "ssh_pin_mismatch", "ssh_temporary_directory_failed",
		"ssh_banner_timeout", "ssh_connect_timeout", "ssh_connection_reset":
		return fmt.Errorf("automation_status_unavailable (%s)", diagnostic.Code)
	default:
		return errors.New("automation_status_unavailable")
	}
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
