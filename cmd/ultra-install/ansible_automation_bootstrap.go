package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"strings"
	"time"

	recoveryassets "github.com/NikitaDmitryuk/ultra/deploy/recovery"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// ansibleBootstrapAutomationGeneration uses the frozen fleet inventory.
// It validates release artifacts before projecting source paths; secrets are not
// included in inventory, process arguments, or public events.
func ansibleBootstrapAutomationGeneration(ctx context.Context, p *installplan.InstallPlan, inventory map[string]any, directory, architecture, python, executable string, generation int) error {
	if p.Automation == nil {
		return fmt.Errorf("automation configuration required")
	}
	a := p.Automation
	manifest, err := verifyAutomationRelease(a.ReleaseDir, a.Version)
	if err != nil {
		return err
	}
	for _, capability := range []string{"service-access-v1", "provider-pool-quota-v1"} {
		if !hasAutomationCapability(manifest, capability) {
			return fmt.Errorf("bootstrap emergency contract unavailable")
		}
	}
	stage := filepath.Join(directory, "automation-sources")
	if err := os.MkdirAll(stage, 0700); err != nil {
		return err
	}
	tools, err := extractUpgradeTools(filepath.Join(a.ReleaseDir, "ultra-recovery.tar.gz"), filepath.Join(stage, "tools"), nil)
	if err != nil {
		return err
	}
	members := []string{}
	selected := []map[string]any{}
	for _, tool := range tools {
		name := filepath.Base(tool["destination"].(string))
		if !strings.HasPrefix(name, "test_") && (filepath.Ext(name) == ".py" || filepath.Ext(name) == ".service" || filepath.Ext(name) == ".timer") {
			selected = append(selected, tool)
			members = append(members, name)
		}
	}
	if !containsAutomationMember(members, "bootstrap_plan.py") {
		return fmt.Errorf("recovery release lacks Ansible bootstrap planner")
	}
	asset, err := upgradeAsset(manifest, "ultra-client-linux-"+architecture)
	if err != nil {
		return err
	}
	selected = append(selected, map[string]any{"source": filepath.Join(a.ReleaseDir, asset.Name), "destination": "/usr/local/bin/ultra-client", "mode": "0755", "sha256": asset.SHA})
	installer, err := upgradeAsset(manifest, "ultra-install-linux-"+architecture)
	if err != nil {
		return err
	}
	runtime, err := upgradeAsset(manifest, "ultra-ansible-runtime-linux-"+architecture+".tar.gz")
	if err != nil {
		return err
	}
	emergency, err := upgradeAsset(manifest, "ultra-relay-linux-"+architecture)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	configuration := map[string]any{}
	if err := json.Unmarshal(raw, &configuration); err != nil {
		return err
	}
	configuration["database"] = p.Database.Name
	if p.Database.Name == "" {
		configuration["database"] = "ultra_db"
	}
	configuration["spec"] = filepath.Join(p.Bridge.RemoteDir, "spec.json")
	configuration["architecture"] = architecture
	configuration["recovery_tool_members"] = members
	configuration["tools"] = selected
	controllerDirectory := managedControllerDirectory(a.Version)
	configuration["controller_directory"] = controllerDirectory
	compute, dns, err := prepareProviderSecrets(p, stage)
	if err != nil {
		return err
	}
	if compute != "" {
		configuration["cloud_key_file"] = compute
	}
	if dns != "" {
		configuration["dns"].(map[string]any)["api_key_file"] = dns
	}
	planner, err := recoveryassets.Scripts.ReadFile("bootstrap_plan.py")
	if err != nil {
		return err
	}
	plannerPath := filepath.Join(stage, "bootstrap_plan.py")
	if err := os.WriteFile(plannerPath, planner, 0600); err != nil {
		return err
	}
	variables := map[string]any{
		"ultra_controller_directory":       controllerDirectory,
		"ultra_controller_runtime_archive": filepath.Join(a.ReleaseDir, runtime.Name), "ultra_controller_runtime_sha256": runtime.SHA,
		"ultra_install_source": filepath.Join(a.ReleaseDir, installer.Name), "ultra_install_sha256": installer.SHA,
		"ultra_automation_configuration": configuration, "ultra_automation_tools": selected,
		"ultra_automation_planner_source": plannerPath, "ultra_automation_pins_source": a.KnownHostsFile,
		"ultra_automation_cloud_source": compute, "ultra_automation_dns_source": dns,
		"ultra_automation_manifest_source":  filepath.Join(a.ReleaseDir, "release-manifest.json"),
		"ultra_automation_emergency_source": filepath.Join(a.ReleaseDir, emergency.Name),
	}
	if err = automationSignatureInput(a.ReleaseDir, variables); err != nil {
		return err
	}
	configuration["release_signature"] = variables["ultra_automation_signature_source"] != ""
	_, err = runBootstrapMutationStage(ctx, "bootstrap-automation", inventory, variables, directory, "automation", generation, python, executable)
	return err
}

func containsAutomationMember(members []string, name string) bool {
	for _, member := range members {
		if member == name {
			return true
		}
	}
	return false
}

func hasAutomationCapability(manifest *automationRelease, name string) bool {
	for _, capability := range manifest.Capabilities {
		if capability == name {
			return true
		}
	}
	return false
}

// verifyBootstrapAutomation must run after releasing the caller's fleet lease.
// Each observation is a separate bounded read so reconcile and backup can acquire
// the infrastructure lease between observations; success records fresh evidence.
func verifyBootstrapAutomation(ctx context.Context, p *installplan.InstallPlan, inventory map[string]any, directory, python, executable string, generation int) error {
	if generation < 1 || generation > 100 {
		return fmt.Errorf("automation generation invalid")
	}
	raw, err := readBootstrapGenerationInput(filepath.Join(bootstrapMutationStage(directory, "automation", generation), "result.json"))
	if err != nil {
		return err
	}
	var configured struct {
		Configured  bool  `json:"configured"`
		ActivatedAt int64 `json:"activated_at"`
	}
	if json.Unmarshal(raw, &configured) != nil || !configured.Configured || configured.ActivatedAt <= 0 {
		return fmt.Errorf("automation configuration receipt missing")
	}
	if p.Automation == nil {
		return fmt.Errorf("automation configuration required")
	}
	timeout := time.Duration(p.Automation.ReadinessTimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 900 * time.Second
	}
	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	variables := map[string]any{"ultra_automation_activated_at": configured.ActivatedAt,
		"ultra_automation_version":         p.Automation.Version,
		"ultra_automation_manifest_source": filepath.Join(p.Automation.ReleaseDir, "release-manifest.json")}
	if err := automationSignatureInput(p.Automation.ReleaseDir, variables); err != nil {
		return err
	}
	for {
		attempt := filepath.Join(directory, "verify-automation", uuid.NewString())
		receipt, err := deployansible.RunLocal(deadline, "verify-bootstrap-automation", inventory, variables, attempt, python, executable)
		if err == nil && receipt.Result.Values["verified"] == true {
			return nil
		}
		select {
		case <-deadline.Done():
			return fmt.Errorf("automation readiness unavailable: %w", deadline.Err())
		case <-time.After(5 * time.Second):
		}
	}
}

func automationSignatureInput(directory string, variables map[string]any) error {
	path := filepath.Join(directory, "release-manifest.json.minisig")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		variables["ultra_automation_signature_source"] = ""
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect release signature: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 16384 {
		return fmt.Errorf("invalid release signature file")
	}
	variables["ultra_automation_signature_source"] = path
	return nil
}
