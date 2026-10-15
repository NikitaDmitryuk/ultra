package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnsibleReleaseRequiresCompleteCrossArchitectureBundle(t *testing.T) {
	directory := t.TempDir()
	names := []string{
		"ultra-relay-linux-amd64",
		"ultra-relay-linux-arm64",
		"ultra-bot-linux-amd64",
		"ultra-bot-linux-arm64",
		"ultra-client-linux-amd64",
		"ultra-client-linux-arm64",
		"ultra-recovery.tar.gz",
		"ultra-install-linux-amd64",
		"ultra-install-linux-arm64",
		"ultra-ansible.tar.gz",
		"ultra-ansible-runtime-linux-amd64.tar.gz",
		"ultra-ansible-runtime-linux-arm64.tar.gz",
		"mobile-bootstrap.sh",
		"checksums.txt",
	}
	assets := make([]map[string]any, 0, len(names))
	for _, name := range names {
		payload := []byte(name)
		digest := sha256.Sum256(payload)
		if err := os.WriteFile(filepath.Join(directory, name), payload, 0600); err != nil {
			t.Fatal(err)
		}
		assets = append(assets, map[string]any{"name": name, "sha256": hex.EncodeToString(digest[:]), "size": len(payload)})
	}
	manifest := map[string]any{
		"schema_version":      1,
		"version":             "v2.5.0",
		"source_commit":       strings.Repeat("a", 40),
		"database_schema_min": 24,
		"database_schema_max": 25,
		"capabilities":        []string{"service-access-v1", "provider-pool-quota-v1", "lifecycle-gate-v1", "ansible-deploy-v1"},
		"assets":              assets,
	}
	verify := func() error {
		t.Helper()
		raw, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(directory, "release-manifest.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		_, err = verifyAutomationRelease(directory, "v2.5.0")
		return err
	}
	if err := verify(); err != nil {
		t.Fatal(err)
	}
	for index, name := range names {
		t.Run("missing-"+name, func(t *testing.T) {
			partial := append([]map[string]any{}, assets[:index]...)
			manifest["assets"] = append(partial, assets[index+1:]...)
			if verify() == nil {
				t.Fatal("incomplete advertised Ansible contract accepted")
			}
		})
	}
	manifest["assets"] = assets
	for _, change := range []struct {
		key   string
		value any
	}{{"schema_version", 0}, {"source_commit", "unknown"}, {"database_schema_min", 0}, {"database_schema_max", 23}, {"capabilities", []string{"service-access-v1", "ansible-deploy-v1"}}} {
		previous := manifest[change.key]
		manifest[change.key] = change.value
		if verify() == nil {
			t.Fatalf("invalid %s accepted", change.key)
		}
		manifest[change.key] = previous
	}
}
