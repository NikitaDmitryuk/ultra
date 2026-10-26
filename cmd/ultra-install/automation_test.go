package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestProductionCandidateReleaseBindsManifestCommitAndExecutable(t *testing.T) {
	directory := t.TempDir()
	commit := strings.Repeat("a", 40)
	commitNumber, ok := new(big.Int).SetString(commit, 16)
	if !ok {
		t.Fatal("failed to parse fixture commit")
	}
	version := "v0.0." + commitNumber.String()
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
	current := filepath.Join(t.TempDir(), "installer")
	for _, name := range names {
		contents := []byte("fixture:" + name)
		if name == "ultra-install-linux-"+runtime.GOARCH {
			contents = []byte("running-installer")
			if err := os.WriteFile(current, contents, 0700); err != nil {
				t.Fatal(err)
			}
		}
		sum := sha256.Sum256(contents)
		assets = append(assets, map[string]any{"name": name, "sha256": hex.EncodeToString(sum[:]), "size": len(contents)})
		if err := os.WriteFile(filepath.Join(directory, name), contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	manifest := map[string]any{
		"schema_version":      1,
		"version":             version,
		"source_commit":       commit,
		"database_schema_min": 24,
		"database_schema_max": 25,
		"capabilities":        []string{"service-access-v1", "provider-pool-quota-v1", "lifecycle-gate-v1", "ansible-deploy-v1"},
		"assets":              assets,
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, "release-manifest.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	manifestSHA := digestSHA256(raw)
	if _, err = verifyProductionCandidateRelease(directory, commit, version, manifestSHA, current); err != nil {
		t.Fatalf("verified operator candidate rejected: %v", err)
	}
	for name, fields := range map[string][3]string{
		"commit":     {strings.Repeat("b", 40), version, manifestSHA},
		"manifest":   {commit, version, strings.Repeat("0", 64)},
		"version":    {commit, "v2.5.1", manifestSHA},
		"executable": {commit, version, manifestSHA},
	} {
		t.Run(name, func(t *testing.T) {
			executable := current
			if name == "executable" {
				executable = filepath.Join(t.TempDir(), "wrong")
				if err := os.WriteFile(executable, []byte("wrong"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := verifyProductionCandidateRelease(directory, fields[0], fields[1], fields[2], executable); err == nil {
				t.Fatal("mismatched operator candidate identity was accepted")
			}
		})
	}
}

func TestAutomationReleasePreflightRejectsIncompleteAndModified(t *testing.T) {
	dir := t.TempDir()
	p := installplan.LegacyValuesToPlan(
		map[string]string{"BRIDGE_IP": "192.0.2.1", "MAIN_EXIT_IP": "192.0.2.2", "REALITY_DEST": "example.com:443"},
	)
	p.Bridge.ReuseSpec = true
	p.Automation = &installplan.AutomationConfig{
		ReleaseDir:     dir,
		Version:        "v1.2.3",
		AgeRecipient:   "age1test",
		BridgeProvider: "a",
		BridgeIPv4:     "192.0.2.1",
		BridgeURL:      "https://example.com/happ",
		KnownHostsFile: "/pins",
		StaticNodes:    []installplan.AutomationNode{{Name: "NL", Address: "192.0.2.2", Provider: "a"}},
	}
	names := []string{
		"ultra-relay-linux-amd64",
		"ultra-relay-linux-arm64",
		"ultra-bot-linux-amd64",
		"ultra-bot-linux-arm64",
		"ultra-client-linux-amd64",
		"ultra-client-linux-arm64",
		"ultra-recovery.tar.gz",
	}
	var assets []map[string]any
	for _, name := range names {
		data := []byte(name)
		sum := sha256.Sum256(data)
		assets = append(assets, map[string]any{"name": name, "size": len(data), "sha256": hex.EncodeToString(sum[:])})
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	manifest := map[string]any{"version": "v1.2.3", "capabilities": []string{"service-access-v1"}, "assets": assets}
	write := func() {
		raw, _ := json.Marshal(manifest)
		if err := os.WriteFile(filepath.Join(dir, "release-manifest.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	if err := preflightAutomation(p); err != nil {
		t.Fatal(err)
	}
	p.Automation.ReleaseDir = filepath.Join(dir, "missing-remote-path")
	statusPlan, err := statusPlanWithRelease(p, dir)
	if err != nil || statusPlan.Automation.ReleaseDir != dir || p.Automation.ReleaseDir == dir {
		t.Fatalf("status override changed canonical plan or failed: %v", err)
	}
	p.Automation.Version = "v9.9.9"
	if _, err := statusPlanWithRelease(p, dir); err == nil {
		t.Fatal("status accepted another release version")
	}
	p.Automation.Version, p.Automation.ReleaseDir = "v1.2.3", dir
	manifest["assets"] = assets[:len(assets)-1]
	write()
	if preflightAutomation(p) == nil {
		t.Fatal("partial release accepted")
	}
	manifest["assets"] = assets
	write()
	if err := os.WriteFile(filepath.Join(dir, names[0]), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if preflightAutomation(p) == nil {
		t.Fatal("modified binary accepted")
	}
	if err := os.Remove(filepath.Join(dir, names[0])); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "binary")
	if err := os.WriteFile(outside, []byte(names[0]), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, names[0])); err != nil {
		t.Fatal(err)
	}
	if preflightAutomation(p) == nil {
		t.Fatal("release asset symlink accepted")
	}
}
