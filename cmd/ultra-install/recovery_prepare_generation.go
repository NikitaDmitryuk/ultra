package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	ansibleassets "github.com/NikitaDmitryuk/ultra/deploy/ansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func recoveryPreparationGeneration(r recoveryPreparationRequest, in recoveryPreparationInputs) (map[string]any, error) {
	controller, variables, err := recoveryPreparationControllerGeneration(r)
	if err != nil {
		return nil, err
	}
	baseline, err := verifyAutomationRelease(filepath.Dir(r.BaselineManifestPath), "")
	if err != nil {
		return nil, err
	}
	p, err := installplan.LoadConfig(r.ConfigPath)
	if err != nil || p.Automation == nil {
		return nil, errors.New("recovery_preparation_config_invalid")
	}
	stage := filepath.Join(r.StateDirectory, "sources")
	if err = ensurePrivateBootstrapDirectory(stage); err != nil {
		return nil, err
	}
	snapshot := filepath.Join("/opt/ultra-ansible/recovery-tools", r.ToolsManifestSHA256)
	baselineSnapshot := filepath.Join("/opt/ultra-recovery/releases", baseline.Version)
	remote := filepath.Join("/var/lib/ultra-ansible/recovery-preparation", r.digest())
	directories := map[string]bool{
		"/opt/ultra-ansible/recovery-tools":           true,
		snapshot:                                      true,
		filepath.Join(snapshot, "recovery"):           true,
		"/opt/ultra-recovery":                         true,
		"/opt/ultra-recovery/releases":                true,
		baselineSnapshot:                              true,
		"/etc/ultra-recovery":                         true,
		"/var/lib/ultra-automation":                   true,
		"/var/lib/ultra-recovery":                     true,
		"/var/lib/ultra-recovery-reconcile":           true,
		"/var/lib/ultra-ansible/recovery-preparation": true,
		remote: true,
	}
	files := []map[string]any{}
	add := func(source, destination, mode, sha string) {
		files = append(files, map[string]any{"source": source, "destination": destination, "mode": mode, "sha256": sha})
		directories[filepath.Dir(destination)] = true
	}
	activeTools := map[string]map[string]any{}
	baselineTools := map[string]string{}
	for _, release := range []struct{ source, subdir, destination string }{{r.ToolsReleaseDirectory, "candidate", filepath.Join(snapshot, "recovery")}, {filepath.Dir(r.BaselineManifestPath), "baseline", baselineSnapshot}} {
		tools, e := extractUpgradeTools(filepath.Join(release.source, "ultra-recovery.tar.gz"), filepath.Join(stage, release.subdir), nil)
		if e != nil {
			return nil, e
		}
		if release.subdir == "candidate" {
			if e = requireUpgradeTool(tools, "live_tools.py"); e != nil {
				return nil, e
			}
		}
		for _, tool := range tools {
			name := filepath.Base(tool["destination"].(string))
			if strings.HasPrefix(name, "test_") {
				continue
			}
			ext := filepath.Ext(name)
			if ext != ".py" && ext != ".service" && ext != ".timer" {
				continue
			}
			sha, e := sourceSHA(tool["source"].(string))
			if e != nil {
				return nil, e
			}
			add(tool["source"].(string), filepath.Join(release.destination, name), "0600", sha)
			if release.subdir == "candidate" {
				activeTools[name] = map[string]any{"source": tool["source"], "sha256": sha}
			} else {
				baselineTools[name] = sha
			}
		}
	}
	activeInventory := map[string]string{}
	activeNames := make([]string, 0, len(activeTools))
	for name := range activeTools {
		activeNames = append(activeNames, name)
	}
	sort.Strings(activeNames)
	for _, name := range activeNames {
		tool := activeTools[name]
		destination := filepath.Join("/opt/ultra-recovery", name)
		mode := "0600"
		if filepath.Ext(name) != ".py" {
			destination = filepath.Join("/etc/systemd/system", name)
			mode = "0644"
		}
		add(tool["source"].(string), destination, mode, tool["sha256"].(string))
		allowed := []string{tool["sha256"].(string)}
		if old := baselineTools[name]; old != "" {
			allowed = append(allowed, old)
		}
		files[len(files)-1]["allowed_sha256"] = allowed
		activeInventory[destination] = tool["sha256"].(string)
		if filepath.Ext(name) != ".py" {
			bundleDestination := filepath.Join("/opt/ultra-recovery", name)
			add(tool["source"].(string), bundleDestination, mode, tool["sha256"].(string))
			files[len(files)-1]["allowed_sha256"] = allowed
			activeInventory[bundleDestination] = tool["sha256"].(string)
		}

	}
	add(
		filepath.Join(r.ToolsReleaseDirectory, "release-manifest.json"),
		"/opt/ultra-recovery/tools-manifest.json",
		"0600",
		r.ToolsManifestSHA256,
	)
	archiveSHA, e := sourceSHA(filepath.Join(r.ToolsReleaseDirectory, "ultra-recovery.tar.gz"))
	if e != nil {
		return nil, e
	}
	add(filepath.Join(r.ToolsReleaseDirectory, "ultra-recovery.tar.gz"), "/opt/ultra-recovery/tools.tar.gz", "0600", archiveSHA)
	// The active and emergency manifests remain exact ORIGINAL release bytes.
	for _, dest := range []string{"/opt/ultra-recovery/release-manifest.json", "/usr/local/libexec/ultra-emergency-manifest.json", "/var/lib/ultra-automation/release-manifest.json", filepath.Join(baselineSnapshot, "release-manifest.json")} {
		add(r.BaselineManifestPath, dest, "0600", r.BaselineManifestSHA256)
	}
	add(
		filepath.Join(r.ToolsReleaseDirectory, "release-manifest.json"),
		filepath.Join(snapshot, "tools-manifest.json"),
		"0600",
		r.ToolsManifestSHA256,
	)
	all := in.retained.Inventory["all"].(map[string]any)
	bridge := all["children"].(map[string]any)["bridge"].(map[string]any)["hosts"].(map[string]any)["bridge"].(map[string]any)
	relaySource := filepath.Join(filepath.Dir(r.BaselineManifestPath), filepath.Base(bridge["ultra_relay_source"].(string)))
	relaySHA := bridge["ultra_relay_sha256"].(string)
	arch := strings.TrimPrefix(filepath.Base(relaySource), "ultra-relay-linux-")
	add(relaySource, "/usr/local/libexec/ultra-relay-emergency", "0755", relaySHA)
	apps := map[string]string{}
	for _, name := range []string{"ultra-relay", "ultra-bot"} {
		asset, e := upgradeAsset(baseline, name+"-linux-"+arch)
		if e != nil {
			return nil, e
		}
		apps["/usr/local/bin/"+name] = asset.SHA
	}
	// Original client/installer are recovery tools: restore only when absent,
	// or accept exact-existing bytes, without installing relay/bot applications.
	for _, name := range []string{"ultra-client", "ultra-install"} {
		asset, e := upgradeAsset(baseline, name+"-linux-"+arch)
		if e != nil {
			return nil, e
		}
		add(filepath.Join(filepath.Dir(r.BaselineManifestPath), asset.Name), "/usr/local/bin/"+name, "0755", asset.SHA)
	}
	helper, err := ansibleassets.Bundle.ReadFile("roles/recovery_preparation/files/prepare.py")
	if err != nil {
		return nil, err
	}
	helperPath := filepath.Join(stage, "prepare.py")
	if err = os.WriteFile(helperPath, helper, 0600); err != nil {
		return nil, err
	}
	add(helperPath, filepath.Join(snapshot, "prepare.py"), "0600", digestSHA256(helper))
	enforcementHelper, err := ansibleassets.Bundle.ReadFile("library/ultra_controller_enforcement.py")
	if err != nil {
		return nil, err
	}
	enforcementPath := filepath.Join(stage, "controller-enforcement.py")
	if err = os.WriteFile(enforcementPath, enforcementHelper, 0600); err != nil {
		return nil, err
	}
	add(enforcementPath, filepath.Join(snapshot, "controller-enforcement.py"), "0600", digestSHA256(enforcementHelper))

	// Foreground reconcile uses the candidate adapter and pinned normal runtime;
	// installed application executables and the selected broker remain unchanged.
	shim := []byte(
		"#!/bin/sh\nset -eu\n[ \"${1-}\" = ansible-run ] || exit 64\nexec " + controller + "/ultra-install \"$@\" --executable " + controller + "/venv/bin/ansible-playbook\n",
	)
	shimPath := filepath.Join(stage, "recovery-tools-installer")
	if err = os.WriteFile(shimPath, shim, 0600); err != nil {
		return nil, err
	}
	add(shimPath, filepath.Join(snapshot, "recovery-tools-installer"), "0755", digestSHA256(shim))
	raw, _ := json.Marshal(p.Automation)
	configuration := map[string]any{}
	_ = json.Unmarshal(raw, &configuration)
	configuration["version"] = baseline.Version
	configuration["database"] = in.retained.Primary.Database
	configuration["database_host"] = p.Database.PrimaryHost
	configuration["spec"] = filepath.Join(p.Bridge.RemoteDir, "spec.json")
	configuration["tools"] = []any{}
	configuration["recovery_tool_members"] = []any{}
	configuration["controller_directory"] = managedControllerDirectory(baseline.Version)
	configuration["known_hosts_file"] = filepath.Join(snapshot, "known_hosts")
	configuration["release_signature"] = false
	if dns, ok := configuration["dns"].(map[string]any); ok {
		dns["api_key_file"] = "/var/lib/ultra-relay/automation/vultr-api-key"
	}
	pins, err := readRebuildInput(r.KnownHostsPath, false)
	if err != nil {
		return nil, err
	}
	add(r.KnownHostsPath, filepath.Join(snapshot, "known_hosts"), "0600", digestSHA256(pins))
	payload := map[string]any{
		"request_sha256":                 r.digest(),
		"tools_manifest_sha256":          r.ToolsManifestSHA256,
		"baseline_manifest_sha256":       r.BaselineManifestSHA256,
		"baseline_version":               baseline.Version,
		"baseline_relay_sha256":          relaySHA,
		"snapshot":                       snapshot,
		"baseline_snapshot":              baselineSnapshot,
		"candidate_controller_directory": controller,
		"active_inventory":               activeInventory,
		"configuration":                  configuration,
		"primary":                        in.retained.Primary,
		"remote_phase_receipt":           filepath.Join(remote, "tools_staged.json"),
	}
	dirs := []string{}
	for directory := range directories {
		dirs = append(dirs, directory)
	}
	sort.Strings(dirs)
	snapshotInventory := map[string]string{}
	for _, file := range files {
		dest := file["destination"].(string)
		if strings.HasPrefix(dest, snapshot+"/") {
			snapshotInventory[strings.TrimPrefix(dest, snapshot+"/")] = file["sha256"].(string)
		}
	}
	payload["snapshot_inventory"] = snapshotInventory
	ancestors := map[string]bool{}
	for _, directory := range dirs {
		for path := directory; ; path = filepath.Dir(path) {
			ancestors[path] = true
			if path == "/" {
				break
			}
		}
	}
	ancestorPaths := []string{}
	for path := range ancestors {
		ancestorPaths = append(ancestorPaths, path)
	}
	sort.Strings(ancestorPaths)
	variables["ultra_lock_directory"] = "/var/lib/ultra-ansible"
	variables["ultra_preparation_ancestors"] = ancestorPaths
	variables["ultra_preparation_snapshot"] = snapshot
	variables["ultra_preparation_remote_directory"] = remote
	variables["ultra_preparation_directories"] = dirs
	variables["ultra_preparation_files"] = files
	variables["ultra_preparation_payload"] = payload
	variables["ultra_preparation_app_binaries"] = apps
	return variables, nil
}

// The live tools release is independent of the application fallback manifest.
// Its raw manifest authenticates the archive; the complete derived inventory is
// checked again on the target before it becomes a reconciliation source.
func upgradeLiveToolsIdentity(
	directory, release, manifestSHA string,
	tools []map[string]any,
	previous map[string]string,
) ([]map[string]any, error) {
	if len(previous) != 0 && len(previous) != 3 {
		return nil, errors.New("upgrade_tools_identity_incomplete")
	}
	for _, name := range []string{"tools-manifest.json", "tools.tar.gz", "tools-inventory.json"} {
		if len(previous) > 0 && !runtimeHostValidDigest(previous[name]) {
			return nil, errors.New("upgrade_tools_identity_invalid")
		}
	}
	members := map[string]string{}
	for _, tool := range tools {
		name := filepath.Base(tool["destination"].(string))
		if strings.HasPrefix(name, "test_") {
			continue
		}
		ext := filepath.Ext(name)
		if ext == ".py" || ext == ".service" || ext == ".timer" {
			members[name] = tool["sha256"].(string)
		}
	}
	inventory, _ := json.Marshal(map[string]any{"protocol": "ultra-recovery-tools-v1", "manifest_sha256": manifestSHA, "members": members})
	source := filepath.Join(directory, "tools-inventory.json")
	if err := writeUpgradeInput(source, inventory); err != nil {
		return nil, err
	}
	entries := []map[string]any{}
	for _, item := range []struct{ Name, Source string }{{"tools-manifest.json", filepath.Join(release, "release-manifest.json")}, {"tools.tar.gz", filepath.Join(release, "ultra-recovery.tar.gz")}, {"tools-inventory.json", source}} {
		sha, err := sourceSHA(item.Source)
		if err != nil {
			return nil, err
		}
		entries = append(
			entries,
			map[string]any{
				"name":            item.Name,
				"source":          item.Source,
				"destination":     "/opt/ultra-recovery/" + item.Name,
				"sha256":          sha,
				"previous_sha256": previous[item.Name],
			},
		)
	}
	return entries, nil
}
