package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	recoveryassets "github.com/NikitaDmitryuk/ultra/deploy/recovery"
)

func TestEmbeddedRecoveryArchiveAndLiveToolsVerifierAgreeOnSSHPolicy(t *testing.T) {
	root := t.TempDir()
	release := filepath.Join(root, "release")
	identityDir := filepath.Join(root, "identity")
	recoveryRoot := filepath.Join(root, "opt", "ultra-recovery")
	systemRoot := filepath.Join(root, "etc", "systemd", "system")
	for _, dir := range []string{release, identityDir, recoveryRoot, systemRoot} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}

	archiveBytes := embeddedRecoveryContractArchive(t)
	archivePath := filepath.Join(release, "ultra-recovery.tar.gz")
	if err := os.WriteFile(archivePath, archiveBytes, 0600); err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := json.Marshal(map[string]any{"assets": []map[string]any{{
		"name": "ultra-recovery.tar.gz", "size": len(archiveBytes), "sha256": digestSHA256(archiveBytes),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(release, "release-manifest.json")
	if err = os.WriteFile(manifestPath, manifestRaw, 0600); err != nil {
		t.Fatal(err)
	}

	tools, err := extractUpgradeTools(archivePath, filepath.Join(root, "extracted"), nil)
	if err != nil {
		t.Fatal(err)
	}
	identityEntries, err := upgradeLiveToolsIdentity(identityDir, release, digestSHA256(manifestRaw), tools, nil)
	if err != nil {
		t.Fatal(err)
	}
	policySeen := false
	for _, tool := range tools {
		name := filepath.Base(tool["destination"].(string))
		destination := filepath.Join(recoveryRoot, name)
		if name == "ssh_policy.json" {
			policySeen = true
			if filepath.Dir(destination) != recoveryRoot {
				t.Fatalf("SSH policy was projected outside recovery root: %s", destination)
			}
		}
		mode, err := os.FileMode(0600), error(nil)
		if rawMode, ok := tool["mode"].(string); ok {
			mode, err = parseRecoveryToolMode(rawMode)
			if err != nil {
				t.Fatal(err)
			}
		}
		data, readErr := os.ReadFile(tool["source"].(string))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if err = os.WriteFile(destination, data, mode); err != nil {
			t.Fatal(err)
		}
		if err = os.Chmod(destination, mode); err != nil {
			t.Fatal(err)
		}
		if isRecoverySystemdUnit(name) {
			systemDestination := filepath.Join(systemRoot, name)
			if err = os.WriteFile(systemDestination, data, mode); err != nil {
				t.Fatal(err)
			}
			if err = os.Chmod(systemDestination, mode); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !policySeen {
		t.Fatal("embedded recovery archive did not yield ssh_policy.json")
	}
	for _, entry := range identityEntries {
		destination := filepath.Join(recoveryRoot, entry["name"].(string))
		data, readErr := os.ReadFile(entry["source"].(string))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if err = os.WriteFile(destination, data, 0600); err != nil {
			t.Fatal(err)
		}
	}

	modulePath := filepath.Join("..", "..", "deploy", "recovery", "live_tools.py")
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for the cross-language recovery contract")
	}
	verify := func() *exec.Cmd {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		t.Cleanup(cancel)
		code := "import importlib.util,pathlib,sys; s=importlib.util.spec_from_file_location('live_tools',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); m.ROOT=pathlib.Path(sys.argv[2]); m.SYSTEM=pathlib.Path(sys.argv[3]); m.verify(dispatcher=False)"
		return exec.CommandContext(ctx, python, "-c", code, modulePath, recoveryRoot, systemRoot)
	}
	if output, runErr := verify().CombinedOutput(); runErr != nil {
		t.Fatalf("embedded archive inventory failed live_tools.verify: %v\n%s", runErr, output)
	}
	policyPath := filepath.Join(recoveryRoot, "ssh_policy.json")
	policyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(policyPath, append(policyBytes, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if output, runErr := verify().CombinedOutput(); runErr == nil || !strings.Contains(string(output), "recovery_tools_member_changed") {
		t.Fatalf("modified SSH policy did not fail the real verifier digest check: err=%v output=%s", runErr, output)
	}
}

func embeddedRecoveryContractArchive(t *testing.T) []byte {
	t.Helper()
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	archive := tar.NewWriter(compressed)
	entries := map[string][]byte{}
	embedded, err := recoveryassets.Scripts.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range embedded {
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, "test_") || strings.HasPrefix(name, "vm_") {
			continue
		}
		ext := filepath.Ext(name)
		if ext != ".py" && name != "ssh_policy.json" {
			continue
		}
		contents, readErr := recoveryassets.Scripts.ReadFile(name)
		if readErr != nil {
			t.Fatal(readErr)
		}
		entries[name] = contents
	}
	// The embedded source tree carries Python and policy data; these real unit
	// names exercise the systemd projection used by the recovery verifier.
	entries["ultra-recovery-backup.service"] = []byte("[Unit]\nDescription=Recovery backup fixture\n")
	entries["ultra-recovery-backup.timer"] = []byte("[Unit]\nDescription=Recovery backup timer fixture\n")
	for _, name := range []string{"recovery.py", "monitor.py", "heartbeat.py", "reconcile.py", "ssh_policy.py", "ssh_policy.json"} {
		if _, ok := entries[name]; !ok {
			t.Fatalf("embedded recovery scripts lack required archive member %s", name)
		}
	}
	for name, contents := range entries {
		if err = archive.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(contents)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err = archive.Write(contents); err != nil {
			t.Fatal(err)
		}
	}
	if err = archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err = compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func parseRecoveryToolMode(raw string) (os.FileMode, error) {
	var mode uint32
	if _, err := fmt.Sscanf(raw, "%o", &mode); err != nil {
		return 0, fmt.Errorf("invalid recovery tool mode %q: %w", raw, err)
	}
	return os.FileMode(mode), nil
}
