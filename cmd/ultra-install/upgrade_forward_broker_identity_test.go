package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestForwardBrokerVariablesBindPreviousAndCandidateIdentities(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	oldDir := filepath.Join(root, "upgrade-v0.0.1")
	activate := filepath.Join(oldDir, "activate")
	if err := os.MkdirAll(activate, 0700); err != nil {
		t.Fatal(err)
	}
	previous := brokerTestManifest("v0.0.0", strings.Repeat("1", 40), "a")
	oldTarget := brokerTestManifest("v0.0.1", strings.Repeat("2", 40), "b")
	newTarget := brokerTestManifest("v0.0.2", strings.Repeat("3", 40), "c")
	previousInstaller, _ := upgradeAsset(previous, "ultra-install-linux-amd64")
	previousRuntime, _ := upgradeAsset(previous, "ultra-ansible-runtime-linux-amd64.tar.gz")
	oldInstaller, _ := upgradeAsset(oldTarget, "ultra-install-linux-amd64")
	oldRuntime, _ := upgradeAsset(oldTarget, "ultra-ansible-runtime-linux-amd64.tar.gz")
	oldManifestRaw, err := json.Marshal(oldTarget)
	if err != nil {
		t.Fatal(err)
	}
	releaseSource := filepath.Join(root, "inputs", "release")
	if err := os.MkdirAll(releaseSource, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(releaseSource, "release-manifest.json"), oldManifestRaw, 0600); err != nil {
		t.Fatal(err)
	}
	vars := map[string]any{
		"ultra_architecture":                    "amd64",
		"ultra_lifecycle_id":                    lifecycleID(oldDir),
		"ultra_previous_manifest":               previous,
		"ultra_previous_manifest_sha256":        strings.Repeat("d", 64),
		"ultra_previous_controller_directory":   managedControllerDirectory(previous.Version),
		"ultra_previous_controller_unit_sha256": strings.Repeat("e", 64),
		"ultra_release_manifest":                oldTarget,
		"ultra_release_manifest_sha256":         digestSHA256(oldManifestRaw),
		"ultra_release_source":                  releaseSource,
		"ultra_controller_directory":            managedControllerDirectory(oldTarget.Version),
		"ultra_target_controller_unit_sha256":   strings.Repeat("a", 64),
		"ultra_install_sha256":                  oldInstaller.SHA,
		"ultra_controller_runtime_sha256":       oldRuntime.SHA,
	}
	request, err := json.Marshal(map[string]any{"variables": vars})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(activate, "request.json"), request, 0600); err != nil {
		t.Fatal(err)
	}
	proof := map[string]any{"schema_version": 1, "operation": "upgrade",
		"request_sha256": digestSHA256(request), "binary_sha256": digestSHA256(request)}
	for _, name := range []string{"job.json", "receipt.json"} {
		writeForwardJSON(t, filepath.Join(activate, name), proof)
	}
	old := forwardOldOperation{Directory: oldDir, ID: lifecycleID(oldDir)}
	variables, err := forwardBrokerVariables(old, newTarget)
	if err != nil {
		t.Fatal(err)
	}
	identities, ok := variables["ultra_forward_expected_brokers"].([]forwardBrokerIdentity)
	if !ok || len(identities) != 3 {
		t.Fatalf("expected previous, prior target, and signed new target identities: %#v", variables)
	}
	if identities[0].InstallerSHA != previousInstaller.SHA || identities[0].RuntimeSHA != previousRuntime.SHA ||
		identities[1].InstallerSHA != oldInstaller.SHA || identities[1].RuntimeSHA != oldRuntime.SHA {
		t.Fatalf("frozen identities not derived from the predecessor manifests: %#v", identities)
	}
	targetIdentity, ok := variables["ultra_forward_target_broker"].(forwardBrokerIdentity)
	if !ok || identities[2] != targetIdentity || targetIdentity.Directory != managedControllerDirectory(newTarget.Version) ||
		targetIdentity.InstallerSHA != newTarget.Assets[0].SHA {
		t.Fatalf("signed target identity was not admitted for same-candidate retry: %#v", variables)
	}
}

func brokerTestManifest(version, commit, fill string) *automationRelease {
	manifest := &automationRelease{Version: version, SourceCommit: commit}
	for _, name := range []string{"ultra-install-linux-amd64", "ultra-ansible-runtime-linux-amd64.tar.gz"} {
		manifest.Assets = append(manifest.Assets, struct {
			Name string `json:"name"`
			SHA  string `json:"sha256"`
			Size int64  `json:"size"`
		}{Name: name, SHA: strings.Repeat(fill, 64), Size: 1})
	}
	return manifest
}
