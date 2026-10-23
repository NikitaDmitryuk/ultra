package main

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
)

func isRecoveryToolName(name string) bool {
	if name == "ssh_policy.json" {
		return true
	}
	switch filepath.Ext(name) {
	case ".py", ".service", ".timer":
		return true
	default:
		return false
	}
}

func isRecoverySystemdUnit(name string) bool {
	ext := filepath.Ext(name)
	return ext == ".service" || ext == ".timer"
}

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
		if isRecoveryToolName(name) {
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
