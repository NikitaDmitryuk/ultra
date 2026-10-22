package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

type recoveryPreparationRequest struct {
	BridgeReimage           *recoveryBridgeReimage `json:"bridge_reimage,omitempty"`
	KnownHostsPath          string                 `json:"known_hosts_path"`
	KnownHostsSHA256        string                 `json:"known_hosts_sha256"`
	EvidenceSourceDirectory string                 `json:"evidence_source_directory"`
	BaselineSourceDirectory string                 `json:"baseline_source_directory"`
	Protocol                string                 `json:"protocol"`
	RetainedDirectory       string                 `json:"retained_directory"`
	ConfigPath              string                 `json:"config_path"`
	BaselineManifestPath    string                 `json:"baseline_manifest_path"`
	OriginalJournalPath     string                 `json:"original_journal_path"`
	ToolsReleaseDirectory   string                 `json:"tools_release_directory"`
	UpgradeConfigPath       string                 `json:"upgrade_config_path"`
	StateDirectory          string                 `json:"state_directory"`
	Python                  string                 `json:"python"`
	Executable              string                 `json:"executable"`
	ConfigSHA256            string                 `json:"config_sha256"`
	UpgradeConfigSHA256     string                 `json:"upgrade_config_sha256"`
	BaselineManifestSHA256  string                 `json:"baseline_manifest_sha256"`
	ToolsManifestSHA256     string                 `json:"tools_manifest_sha256"`
	RetainedFenceSHA256     string                 `json:"retained_fence_sha256"`
	LegacyJournalPath       string                 `json:"legacy_journal_path"`
	LegacyJournalSHA256     string                 `json:"legacy_journal_sha256"`
}

func (r recoveryPreparationRequest) digest() string {
	raw, _ := json.Marshal(r)
	return digestSHA256(raw)
}

func bindRecoveryPreparationRequest(ctx context.Context, r recoveryPreparationRequest) (recoveryPreparationRequest, error) {
	r.Protocol = "ultra-recovery-preparation-request-v1"
	for _, path := range []string{r.RetainedDirectory, r.EvidenceSourceDirectory, r.BaselineSourceDirectory, r.KnownHostsPath, r.ConfigPath, r.BaselineManifestPath, r.OriginalJournalPath, r.LegacyJournalPath, r.ToolsReleaseDirectory, r.UpgradeConfigPath, r.StateDirectory} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return r, errors.New("recovery_preparation_absolute_paths_required")
		}
	}
	if !runtimeHostValidDigest(r.LegacyJournalSHA256) {
		return r, errors.New("recovery_preparation_legacy_binding_required")
	}
	legacyRaw, err := readRebuildInput(r.LegacyJournalPath, true)
	if err != nil || digestSHA256(legacyRaw) != r.LegacyJournalSHA256 {
		return r, errors.New("recovery_preparation_legacy_journal_changed")
	}
	in, err := loadRecoveryPreparationRetainedEvidence(r)
	if err != nil {
		return r, err
	}
	if r.BridgeReimage != nil {
		if err = validateRecoveryBridgeReimage(r.BridgeReimage, legacyRaw, in.retained); err != nil {
			return r, err
		}
	}
	pins, err := readRebuildInput(r.KnownHostsPath, false)
	if err != nil {
		return r, err
	}
	actualPins := digestSHA256(pins)
	if !runtimeHostValidDigest(r.KnownHostsSHA256) || actualPins != r.KnownHostsSHA256 {
		return r, errors.New("recovery_preparation_accepted_pins_changed")
	}
	r.ConfigSHA256 = in.admission.ConfigSHA256
	r.BaselineManifestSHA256 = in.admission.BaselineManifestSHA256
	r.RetainedFenceSHA256 = in.admission.FenceSHA256
	raw, err := readRebuildInput(r.UpgradeConfigPath, true)
	if err != nil {
		return r, err
	}
	r.UpgradeConfigSHA256 = digestSHA256(raw)
	candidate, err := verifyAutomationRelease(r.ToolsReleaseDirectory, "")
	if err != nil {
		return r, err
	}
	p, err := installplan.LoadLifecycleConfig(r.UpgradeConfigPath)
	if err != nil || p.Automation == nil || p.Automation.Version != candidate.Version ||
		p.Automation.ReleaseDir != r.ToolsReleaseDirectory {
		return r, errors.New("recovery_preparation_candidate_config_invalid")
	}
	raw, err = readRebuildInput(filepath.Join(r.ToolsReleaseDirectory, "release-manifest.json"), false)
	if err != nil {
		return r, err
	}
	r.ToolsManifestSHA256 = digestSHA256(raw)
	if err = ensurePrivateBootstrapDirectory(r.StateDirectory); err != nil {
		return r, err
	}
	asset, err := upgradeAsset(candidate, "ultra-ansible-runtime-linux-"+runtime.GOARCH+".tar.gz")
	if err != nil {
		return r, err
	}
	r.Python = "/usr/bin/python3"
	r.Executable, err = preparePinnedAnsibleRuntime(
		ctx,
		filepath.Join(r.StateDirectory, "operator-runtime"),
		filepath.Join(r.ToolsReleaseDirectory, asset.Name),
		asset.SHA,
	)
	if err != nil {
		return r, err
	}
	raw, _ = json.Marshal(r)
	if err = publishRetainedReconcile(filepath.Join(r.StateDirectory, "request.json"), raw); err != nil {
		return r, err
	}
	return r, nil
}

func validateRecoveryPreparationRequest(r recoveryPreparationRequest) (recoveryPreparationInputs, error) {
	var zero recoveryPreparationInputs
	if r.Protocol != "ultra-recovery-preparation-request-v1" || r.Python != "/usr/bin/python3" {
		return zero, errors.New("recovery_preparation_request_invalid")
	}
	raw, err := readRebuildInput(filepath.Join(r.StateDirectory, "request.json"), true)
	encoded, _ := json.Marshal(r)
	if err != nil || string(raw) != string(encoded) {
		return zero, errors.New("recovery_preparation_request_changed")
	}
	for _, sha := range []string{r.ConfigSHA256, r.UpgradeConfigSHA256, r.BaselineManifestSHA256, r.ToolsManifestSHA256, r.RetainedFenceSHA256, r.LegacyJournalSHA256, r.KnownHostsSHA256} {
		if !runtimeHostValidDigest(sha) {
			return zero, errors.New("recovery_preparation_request_invalid")
		}
	}
	in, err := loadRecoveryPreparationRetainedEvidence(r)
	if err != nil {
		return zero, err
	}
	if r.BridgeReimage != nil {
		legacy, e := readRebuildInput(r.LegacyJournalPath, true)
		if e != nil {
			return zero, e
		}
		if e = validateRecoveryBridgeReimage(r.BridgeReimage, legacy, in.retained); e != nil {
			return zero, e
		}
	}
	if in.admission.FenceSHA256 != r.RetainedFenceSHA256 || in.admission.ConfigSHA256 != r.ConfigSHA256 ||
		in.admission.BaselineManifestSHA256 != r.BaselineManifestSHA256 {
		return zero, errors.New("recovery_preparation_baseline_changed")
	}
	for _, file := range []struct{ path, sha string }{{r.LegacyJournalPath, r.LegacyJournalSHA256}, {r.UpgradeConfigPath, r.UpgradeConfigSHA256}, {filepath.Join(r.ToolsReleaseDirectory, "release-manifest.json"), r.ToolsManifestSHA256}} {
		raw, err = readRebuildInput(file.path, (file.path == r.UpgradeConfigPath || file.path == r.LegacyJournalPath))
		if err != nil || digestSHA256(raw) != file.sha {
			return zero, errors.New("recovery_preparation_candidate_changed")
		}
	}
	pins, err := readRebuildInput(r.KnownHostsPath, false)
	if err != nil || digestSHA256(pins) != r.KnownHostsSHA256 {
		return zero, errors.New("recovery_preparation_accepted_pins_changed")
	}
	manifest, err := verifyAutomationRelease(r.ToolsReleaseDirectory, "")
	if err != nil {
		return zero, err
	}
	asset, err := upgradeAsset(manifest, "ultra-ansible-runtime-linux-"+runtime.GOARCH+".tar.gz")
	if err != nil {
		return zero, err
	}
	expected := filepath.Join(r.StateDirectory, "operator-runtime", "runtime-"+asset.SHA, "venv/bin/ansible-playbook")
	if r.Executable != expected ||
		!installedRuntimeMatches(expected, filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(expected))), "ready"), asset.SHA) {
		return zero, errors.New("recovery_preparation_operator_runtime_changed")
	}
	return in, nil
}

// Generation variables are the normal controller renderer contract. Selection,
// unit installation and startup belong to the parent's proof-bound handoff.
func recoveryPreparationControllerGeneration(r recoveryPreparationRequest) (string, map[string]any, error) {
	manifest, err := verifyAutomationRelease(r.ToolsReleaseDirectory, "")
	if err != nil {
		return "", nil, err
	}
	raw, err := os.ReadFile(filepath.Join(r.ToolsReleaseDirectory, "release-manifest.json"))
	if err != nil || digestSHA256(raw) != r.ToolsManifestSHA256 {
		return "", nil, errors.New("recovery_preparation_tools_changed")
	}
	in, err := loadRecoveryPreparationRetainedEvidence(r)
	if err != nil {
		return "", nil, err
	}
	all := in.retained.Inventory["all"].(map[string]any)
	children := all["children"].(map[string]any)
	bridge := children["bridge"].(map[string]any)["hosts"].(map[string]any)["bridge"].(map[string]any)
	arch := filepath.Base(bridge["ultra_relay_source"].(string))
	arch = arch[len("ultra-relay-linux-"):]
	installer, err := upgradeAsset(manifest, "ultra-install-linux-"+arch)
	if err != nil {
		return "", nil, err
	}
	runtimeAsset, err := upgradeAsset(manifest, "ultra-ansible-runtime-linux-"+arch+".tar.gz")
	if err != nil {
		return "", nil, err
	}
	directory := managedControllerDirectory(manifest.Version)
	return directory, map[string]any{
		"ultra_controller_directory":       directory,
		"ultra_controller_runtime_archive": filepath.Join(r.ToolsReleaseDirectory, runtimeAsset.Name),
		"ultra_controller_runtime_sha256":  runtimeAsset.SHA,
		"ultra_install_source":             filepath.Join(r.ToolsReleaseDirectory, installer.Name),
		"ultra_install_sha256":             installer.SHA,
	}, nil
}
