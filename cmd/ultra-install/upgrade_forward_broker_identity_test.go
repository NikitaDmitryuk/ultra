package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func forwardBrokerVariablesFixture(t *testing.T) (forwardOldOperation, *automationRelease, *automationRelease, *automationRelease) {
	t.Helper()
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
	bridge := map[string]any{}
	for _, key := range []string{"ultra_architecture", "ultra_previous_controller_directory", "ultra_previous_controller_unit_sha256", "ultra_controller_directory", "ultra_target_controller_unit_sha256", "ultra_install_sha256", "ultra_controller_runtime_sha256"} {
		bridge[key] = vars[key]
		delete(vars, key)
	}
	vars["ultra_bridge_inventory_host"] = "bridge"
	inventory := map[string]any{"all": map[string]any{"children": map[string]any{
		"bridge": map[string]any{"hosts": map[string]any{"bridge": bridge}},
		"exits":  map[string]any{"hosts": map[string]any{"exit_test": map[string]any{"ultra_architecture": "arm64"}}},
	}}}
	request, err := json.Marshal(map[string]any{"inventory": inventory, "variables": vars})
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
	return forwardOldOperation{Directory: oldDir, ID: lifecycleID(oldDir)}, newTarget, previous, oldTarget
}

func TestForwardBrokerVariablesBindPreviousAndCandidateIdentities(t *testing.T) {
	old, newTarget, previous, oldTarget := forwardBrokerVariablesFixture(t)
	requestRaw, err := os.ReadFile(filepath.Join(old.Directory, "activate", "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var request map[string]any
	if err := json.Unmarshal(requestRaw, &request); err != nil {
		t.Fatal(err)
	}
	variablesInput := request["variables"].(map[string]any)
	bridgeInput := request["inventory"].(map[string]any)["all"].(map[string]any)["children"].(map[string]any)["bridge"].(map[string]any)["hosts"].(map[string]any)["bridge"].(map[string]any)
	for _, key := range []string{"ultra_architecture", "ultra_previous_controller_directory", "ultra_previous_controller_unit_sha256", "ultra_controller_directory", "ultra_target_controller_unit_sha256", "ultra_install_sha256", "ultra_controller_runtime_sha256"} {
		if _, exists := variablesInput[key]; exists || bridgeInput[key] == nil {
			t.Fatalf("fixture must match ansibleUpgrade bridge-host serialization for %s", key)
		}
	}
	previousInstaller, _ := upgradeAsset(previous, "ultra-install-linux-amd64")
	previousRuntime, _ := upgradeAsset(previous, "ultra-ansible-runtime-linux-amd64.tar.gz")
	oldInstaller, _ := upgradeAsset(oldTarget, "ultra-install-linux-amd64")
	oldRuntime, _ := upgradeAsset(oldTarget, "ultra-ansible-runtime-linux-amd64.tar.gz")
	variables, err := forwardBrokerVariables(old, newTarget)
	if err != nil {
		t.Fatal(err)
	}
	identities, ok := variables["ultra_forward_expected_brokers"].([]forwardBrokerIdentity)
	if !ok || len(identities) != 3 {
		t.Fatalf("expected previous, prior target, and signed new target identities: %#v", variables)
	}
	wantPrevious := forwardBrokerIdentity{Directory: managedControllerDirectory(previous.Version), InstallerSHA: previousInstaller.SHA, RuntimeSHA: previousRuntime.SHA, UnitSHA: strings.Repeat("e", 64)}
	wantOld := forwardBrokerIdentity{Directory: managedControllerDirectory(oldTarget.Version), InstallerSHA: oldInstaller.SHA, RuntimeSHA: oldRuntime.SHA, UnitSHA: strings.Repeat("a", 64)}
	if identities[0] != wantPrevious || identities[1] != wantOld {
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

func TestForwardBrokerVariablesOmitUnverifiablePreviousIdentity(t *testing.T) {
	for _, name := range []string{"legacy baseline", "missing source commit", "invalid source commit", "legacy directory", "missing directory", "missing unit hash", "invalid unit hash", "missing installer", "invalid installer hash", "missing runtime", "invalid runtime hash", "ambiguous runtime"} {
		t.Run(name, func(t *testing.T) {
			old, target, _, oldTarget := forwardBrokerVariablesFixture(t)
			path := filepath.Join(old.Directory, "activate", "request.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var request map[string]any
			if err := json.Unmarshal(raw, &request); err != nil {
				t.Fatal(err)
			}
			variables := request["variables"].(map[string]any)
			previous := variables["ultra_previous_manifest"].(map[string]any)
			bridge := request["inventory"].(map[string]any)["all"].(map[string]any)["children"].(map[string]any)["bridge"].(map[string]any)["hosts"].(map[string]any)["bridge"].(map[string]any)
			assets := previous["assets"].([]any)
			switch name {
			case "legacy baseline":
				delete(previous, "source_commit")
				previous["assets"] = assets[:1]
				bridge["ultra_previous_controller_directory"] = "/opt/ultra-ansible/releases/v0.0.0"
			case "missing source commit":
				delete(previous, "source_commit")
			case "invalid source commit":
				previous["source_commit"] = "unknown"
			case "legacy directory":
				bridge["ultra_previous_controller_directory"] = "/opt/ultra-ansible/releases/v0.0.0"
			case "missing directory":
				delete(bridge, "ultra_previous_controller_directory")
			case "missing unit hash":
				delete(bridge, "ultra_previous_controller_unit_sha256")
			case "invalid unit hash":
				bridge["ultra_previous_controller_unit_sha256"] = "unknown"
			case "missing installer":
				previous["assets"] = assets[1:]
			case "invalid installer hash":
				assets[0].(map[string]any)["sha256"] = "unknown"
			case "missing runtime":
				previous["assets"] = assets[:1]
			case "invalid runtime hash":
				assets[1].(map[string]any)["sha256"] = "unknown"
			case "ambiguous runtime":
				previous["assets"] = append(assets, assets[1])
			}
			requestRaw, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, requestRaw, 0600); err != nil {
				t.Fatal(err)
			}
			proof := map[string]any{"schema_version": 1, "operation": "upgrade", "request_sha256": digestSHA256(requestRaw), "binary_sha256": digestSHA256(requestRaw)}
			for _, file := range []string{"job.json", "receipt.json"} {
				writeForwardJSON(t, filepath.Join(old.Directory, "activate", file), proof)
			}
			got, err := forwardBrokerVariables(old, target)
			if err != nil {
				t.Fatal(err)
			}
			identities, ok := got["ultra_forward_expected_brokers"].([]forwardBrokerIdentity)
			oldInstaller, _ := upgradeAsset(oldTarget, "ultra-install-linux-amd64")
			oldRuntime, _ := upgradeAsset(oldTarget, "ultra-ansible-runtime-linux-amd64.tar.gz")
			wantOld := forwardBrokerIdentity{Directory: managedControllerDirectory(oldTarget.Version), InstallerSHA: oldInstaller.SHA, RuntimeSHA: oldRuntime.SHA, UnitSHA: strings.Repeat("a", 64)}
			if !ok || len(identities) != 2 || identities[0] != wantOld || identities[1] != got["ultra_forward_target_broker"] {
				t.Fatalf("expected only exact old target and candidate identities, got %#v", got)
			}
		})
	}
}

func TestForwardBrokerVariablesRejectMalformedBridgeIdentity(t *testing.T) {
	for _, name := range []string{"missing inventory", "missing bridge", "extra bridge", "null bridge", "wrong bridge alias", "missing architecture", "invalid architecture", "missing installer hash", "wrong installer hash", "missing unit hash", "global identity cannot override bridge", "lifecycle must remain in variables"} {
		t.Run(name, func(t *testing.T) {
			old, target, _, _ := forwardBrokerVariablesFixture(t)
			path := filepath.Join(old.Directory, "activate", "request.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var request map[string]any
			if err := json.Unmarshal(raw, &request); err != nil {
				t.Fatal(err)
			}
			variables := request["variables"].(map[string]any)
			children := request["inventory"].(map[string]any)["all"].(map[string]any)["children"].(map[string]any)
			hosts := children["bridge"].(map[string]any)["hosts"].(map[string]any)
			bridge := hosts["bridge"].(map[string]any)
			switch name {
			case "missing inventory":
				delete(request, "inventory")
			case "missing bridge":
				delete(children, "bridge")
			case "extra bridge":
				hosts["other"] = bridge
			case "null bridge":
				hosts["bridge"] = nil
			case "wrong bridge alias":
				hosts["other"] = bridge
				delete(hosts, "bridge")
			case "missing architecture":
				delete(bridge, "ultra_architecture")
			case "invalid architecture":
				bridge["ultra_architecture"] = "386"
			case "missing installer hash":
				delete(bridge, "ultra_install_sha256")
			case "wrong installer hash":
				bridge["ultra_install_sha256"] = strings.Repeat("f", 64)
			case "missing unit hash":
				delete(bridge, "ultra_target_controller_unit_sha256")
			case "global identity cannot override bridge":
				variables["ultra_architecture"] = bridge["ultra_architecture"]
				delete(bridge, "ultra_architecture")
			case "lifecycle must remain in variables":
				bridge["ultra_lifecycle_id"] = variables["ultra_lifecycle_id"]
				delete(variables, "ultra_lifecycle_id")
			}
			requestRaw, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, requestRaw, 0600); err != nil {
				t.Fatal(err)
			}
			// Rebind valid evidence so rejection exercises identity parsing rather than a stale digest.
			proof := map[string]any{"schema_version": 1, "operation": "upgrade", "request_sha256": digestSHA256(requestRaw), "binary_sha256": digestSHA256(requestRaw)}
			for _, file := range []string{"job.json", "receipt.json"} {
				writeForwardJSON(t, filepath.Join(old.Directory, "activate", file), proof)
			}
			if _, err := forwardBrokerVariables(old, target); err == nil || err.Error() != "upgrade_forward_broker_identity_unverified" {
				t.Fatalf("invalid bridge identity accepted: %v", err)
			}
		})
	}
}
