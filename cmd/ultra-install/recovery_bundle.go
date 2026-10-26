package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func requireUpgradeTool(tools []map[string]any, name string) error {
	for _, tool := range tools {
		if filepath.Base(tool["destination"].(string)) == name {
			return nil
		}
	}
	return errors.New("recovery_bundle_incomplete")
}

func extractUpgradeTools(archivePath, directory string, previous map[string]string) ([]map[string]any, error) {
	return extractRecoveryTools(archivePath, directory, previous, true)
}

func extractRecoveryTools(archivePath, directory string, previous map[string]string, requirePolicy bool) ([]map[string]any, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return nil, err
	}
	defer file.Close() //nolint:errcheck
	zipped, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer zipped.Close() //nolint:errcheck
	archive := tar.NewReader(zipped)
	if err = os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	tools := []map[string]any{}
	seen := map[string]bool{}
	total := int64(0)
	for {
		member, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if member.Typeflag != tar.TypeReg ||
			!filepath.IsLocal(member.Name) ||
			(!regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]+\.(py|service|timer)$`).MatchString(member.Name) && member.Name != "ssh_policy.json") ||
			seen[member.Name] ||
			member.Size < 0 ||
			member.Size > 4<<20 ||
			len(seen) >= 64 {
			return nil, errors.New("unsafe_recovery_member")
		}
		total += member.Size
		if total > 32<<20 {
			return nil, errors.New("recovery_bundle_too_large")
		}
		seen[member.Name] = true
		data, err := io.ReadAll(io.LimitReader(archive, member.Size+1))
		if err != nil || int64(len(data)) != member.Size {
			return nil, errors.New("recovery_member_truncated")
		}
		source := filepath.Join(directory, member.Name)
		if err = writeUpgradeInput(source, data); err != nil {
			return nil, err
		}
		hash := sha256.Sum256(data)
		sum := hex.EncodeToString(hash[:])
		destination := "/opt/ultra-recovery/" + member.Name
		mode := "0755"
		if strings.HasSuffix(member.Name, ".service") || strings.HasSuffix(member.Name, ".timer") {
			destination = "/etc/systemd/system/" + member.Name
			mode = "0644"
		}
		key := sha256.Sum256([]byte(destination))
		tools = append(
			tools,
			map[string]any{
				"source":          source,
				"destination":     destination,
				"mode":            mode,
				"sha256":          sum,
				"previous_sha256": previous[member.Name],
				"backup_name":     hex.EncodeToString(key[:]),
			},
		)
	}
	for _, name := range []string{
		"recovery.py", "monitor.py", "heartbeat.py", "reconcile.py",
		"ultra-recovery-backup.service", "ultra-recovery-backup.timer",
	} {
		if !seen[name] {
			return nil, errors.New("recovery_bundle_incomplete")
		}
	}
	if seen["ssh_policy.py"] != seen["ssh_policy.json"] || (requirePolicy && !seen["ssh_policy.py"]) {
		return nil, errors.New("recovery_bundle_incomplete")
	}
	return tools, nil
}

func upgradeAsset(manifest *automationRelease, name string) (struct {
	Name string `json:"name"`
	SHA  string `json:"sha256"`
	Size int64  `json:"size"`
}, error) {
	var result struct {
		Name string `json:"name"`
		SHA  string `json:"sha256"`
		Size int64  `json:"size"`
	}
	found := false
	for _, asset := range manifest.Assets {
		if asset.Name == name {
			if found {
				return result, errors.New("ambiguous_upgrade_asset")
			}
			found = true
			result = asset
		}
	}
	if !found {
		return result, errors.New("missing_upgrade_asset")
	}
	return result, nil
}
