package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestRewriteUpgradeReleaseArgsPinsResolvedBundle(t *testing.T) {
	got := rewriteUpgradeReleaseArgs([]string{
		"--config", "install.config", "--release", "latest", "--release-dir=/tmp/old",
		"--job-dir", "/tmp/job", "--retry-failed",
	}, "/tmp/verified/v1.2.3")
	want := []string{"--config", "install.config", "--job-dir", "/tmp/job", "--retry-failed", "--release-dir", "/tmp/verified/v1.2.3"}
	if len(got) != len(want) {
		t.Fatalf("rewritten args = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rewritten args = %#v, want %#v", got, want)
		}
	}
}

func TestRewriteUpgradeReleaseArgsKeepsPinBeforeFlagTerminator(t *testing.T) {
	got := rewriteUpgradeReleaseArgs([]string{"--"}, "/tmp/verified/v1.2.3")
	want := []string{"--release-dir", "/tmp/verified/v1.2.3"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("rewritten args = %#v, want %#v", got, want)
	}
}

func TestManualUpgradeEnvironmentPreservesResolvedMinisign(t *testing.T) {
	got := manualUpgradeEnvironment("/home/test-user", "/home/test-user/.local/bin/minisign")
	want := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/home/test-user",
		upgradeMinisignPathEnv + "=/home/test-user/.local/bin/minisign",
	}
	if len(got) != len(want) {
		t.Fatalf("environment = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("environment = %#v, want %#v", got, want)
		}
	}
	if got := manualUpgradeEnvironment("", "relative/minisign"); len(got) != 1 {
		t.Fatalf("invalid home or verifier leaked into environment: %#v", got)
	}
}

func TestMinisignVerifierMustBeAvailableForHandoff(t *testing.T) {
	if handed, err := handoffManualUpgrade(context.Background(), &installplan.InstallPlan{}, "", nil, ""); err == nil || handed {
		t.Fatalf("handoff proceeded without the verifier: handed=%v err=%v", handed, err)
	}
	if err := validateMinisignExecutable("relative/minisign"); err == nil {
		t.Fatal("relative verifier path accepted")
	}
	if err := validateMinisignExecutable(filepath.Join(t.TempDir(), "missing-minisign")); err == nil {
		t.Fatal("missing verifier accepted")
	}
	verifier := filepath.Join(t.TempDir(), "minisign")
	if err := os.WriteFile(verifier, []byte("not executable"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateMinisignExecutable(verifier); err == nil {
		t.Fatal("non-executable verifier accepted")
	}
}

func TestStageManualUpgradeInstallerPreservesImmutableRelease(t *testing.T) {
	parent := t.TempDir()
	releaseDir := filepath.Join(parent, "release-v1.2.3")
	if err := os.Mkdir(releaseDir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(releaseDir, 0700) })
	source := filepath.Join(releaseDir, "ultra-install-linux-amd64")
	contents := []byte("#!/bin/sh\n[ \"$1\" = upgrade ]\n")
	if err := os.WriteFile(source, contents, 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(releaseDir, 0500); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	target, cleanup, err := stageManualUpgradeInstaller(releaseDir, filepath.Base(source), hex.EncodeToString(digest[:]), int64(len(contents)))
	if err != nil {
		t.Fatal(err)
	}

	if filepath.Dir(target) == releaseDir {
		t.Fatalf("handoff target is inside signed release: %s", target)
	}
	if info, err := os.Stat(source); err != nil || info.Mode().Perm() != 0400 {
		t.Fatalf("signed source mode changed: info=%v err=%v", info, err)
	}
	if got, err := os.ReadFile(source); err != nil || string(got) != string(contents) {
		t.Fatalf("signed source changed: contents=%q err=%v", got, err)
	}
	if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("staged installer is not private and executable: info=%v err=%v", info, err)
	}
	if err := exec.Command(target, "upgrade").Run(); err != nil {
		t.Fatalf("staged installer did not execute: %v", err)
	}
	cleanup()
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("staged installer was not removed: %v", err)
	}

	if _, _, err := stageManualUpgradeInstaller(releaseDir, filepath.Base(source), strings.Repeat("0", 64), int64(len(contents))); err == nil {
		t.Fatal("mismatched staged installer digest was accepted")
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".ultra-installer-handoff-") {
			t.Fatalf("failed staging left temporary directory %q", entry.Name())
		}
	}
}

func TestVerifyOperatorUpgradeReleaseBindsManifestCommitAndExecutable(t *testing.T) {
	directory := t.TempDir()
	commit := strings.Repeat("a", 40)
	commitNumber, ok := new(big.Int).SetString(commit, 16)
	if !ok {
		t.Fatal("failed to parse fixture commit")
	}
	version := "v0.0." + commitNumber.String()
	names := []string{"ultra-relay-linux-amd64", "ultra-relay-linux-arm64", "ultra-bot-linux-amd64", "ultra-bot-linux-arm64", "ultra-client-linux-amd64", "ultra-client-linux-arm64", "ultra-recovery.tar.gz", "ultra-install-linux-amd64", "ultra-install-linux-arm64", "ultra-ansible.tar.gz", "ultra-ansible-runtime-linux-amd64.tar.gz", "ultra-ansible-runtime-linux-arm64.tar.gz", "mobile-bootstrap.sh", "checksums.txt"}
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
	manifest := map[string]any{"schema_version": 1, "version": version, "source_commit": commit, "database_schema_min": 24, "database_schema_max": 25, "capabilities": []string{"service-access-v1", "provider-pool-quota-v1", "lifecycle-gate-v1", "ansible-deploy-v1"}, "assets": assets}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, "release-manifest.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	manifestSHA := digestSHA256(raw)
	if _, err = verifyOperatorUpgradeRelease(directory, commit, version, manifestSHA, current); err != nil {
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
			if _, err := verifyOperatorUpgradeRelease(directory, fields[0], fields[1], fields[2], executable); err == nil {
				t.Fatal("mismatched operator candidate identity was accepted")
			}
		})
	}
}

func TestAutomationReleasePreflightRejectsIncompleteAndModified(t *testing.T) {
	dir := t.TempDir()
	p := installplan.LegacyValuesToPlan(map[string]string{"BRIDGE_IP": "192.0.2.1", "MAIN_EXIT_IP": "192.0.2.2", "REALITY_DEST": "example.com:443"})
	p.Bridge.ReuseSpec = true
	p.Automation = &installplan.AutomationConfig{ReleaseDir: dir, Version: "v1.2.3", AgeRecipient: "age1test", BridgeProvider: "a", BridgeIPv4: "192.0.2.1", BridgeURL: "https://example.com/happ", KnownHostsFile: "/pins", StaticNodes: []installplan.AutomationNode{{Name: "NL", Address: "192.0.2.2", Provider: "a"}}}
	names := []string{"ultra-relay-linux-amd64", "ultra-relay-linux-arm64", "ultra-bot-linux-amd64", "ultra-bot-linux-arm64", "ultra-client-linux-amd64", "ultra-client-linux-arm64", "ultra-recovery.tar.gz"}
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
