package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestAdoptSSHOverrideRequiresPreparation(t *testing.T) {
	if os.Getenv("ULTRA_TEST_ADOPT_OVERRIDE_CHILD") == "1" {
		runAdoptCommand([]string{"--config", os.Getenv("ULTRA_TEST_ADOPT_CONFIG"), "--bridge-ssh-host", "192.0.2.1"})
		return
	}
	config := filepath.Join(t.TempDir(), "install.config")
	if err := os.WriteFile(config, []byte("BRIDGE=192.0.2.1\nEXIT=192.0.2.2\nIDENTITY=/fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestAdoptSSHOverrideRequiresPreparation$")
	command.Env = []string{"ULTRA_TEST_ADOPT_OVERRIDE_CHILD=1", "ULTRA_TEST_ADOPT_CONFIG=" + config}
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "adoption_ssh_override_requires_preparation") {
		t.Fatalf("override reached inspection: %v: %s", err, output)
	}
}

// The subprocess exercises the CLI's os.Exit error path with a clean operator
// cache. Its generated credentials cannot authorize access to any real host.
func TestAdoptPreparesOfflineRuntimeOnCleanCache(t *testing.T) {
	if os.Getenv("ULTRA_TEST_ADOPT_CHILD") == "1" {
		runAdoptCommand([]string{"--config", os.Getenv("ULTRA_TEST_ADOPT_CONFIG"), "--release-dir", os.Getenv("ULTRA_TEST_OFFLINE_RELEASE")})
		return
	}
	release := os.Getenv("ULTRA_TEST_OFFLINE_RELEASE")
	if release == "" {
		t.Skip("requires explicit isolated release fixture")
	}
	manifest, err := verifyAutomationRelease(release, "")
	if err != nil {
		t.Fatal(err)
	}
	asset, err := upgradeAsset(manifest, "ultra-ansible-runtime-linux-"+runtime.GOARCH+".tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	cache := filepath.Join(root, "cache")
	identity := filepath.Join(root, "identity")
	pins := filepath.Join(root, "known_hosts")
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "isolated adopt regression")
	if err != nil {
		t.Fatal(err)
	}
	host, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{identity: pem.EncodeToMemory(block), pins: append([]byte("127.0.0.1 "), ssh.MarshalAuthorizedKey(host)...)} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	config := filepath.Join(root, "install.config")
	data := fmt.Sprintf("INSTALL_SCHEMA_VERSION=2\nBRIDGE=127.0.0.1\nEXIT=127.0.0.1\nSSH_USER=ultra-adopt-isolated-fixture\nIDENTITY=%s\nULTRA_AUTOMATION_VERSION=unused\nULTRA_AUTOMATION_RELEASE_DIR=/unused\nULTRA_AUTOMATION_AGE_RECIPIENT=age1fixture\nULTRA_AUTOMATION_BRIDGE_PROVIDER=fixture\nULTRA_AUTOMATION_BRIDGE_URL=https://example.com/healthz\nULTRA_AUTOMATION_KNOWN_HOSTS_FILE=%s\nULTRA_AUTOMATION_ADMIN_TELEGRAM_ID=123\nULTRA_AUTOMATION_STATIC_NODES=[{\"name\":\"fixture\",\"address\":\"127.0.0.1\",\"provider\":\"fixture\"}]\n", identity, pins)
	if err := os.WriteFile(config, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAdoptPreparesOfflineRuntimeOnCleanCache$")
	// Explicit environment excludes executor overrides, credentials and user SSH
	// configuration inherited by the test runner.
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + root, "XDG_CACHE_HOME=" + cache, "ULTRA_TEST_ADOPT_CHILD=1", "ULTRA_TEST_ADOPT_CONFIG=" + config, "ULTRA_TEST_OFFLINE_RELEASE=" + release}
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatal(ctx.Err())
	}
	if err == nil || !strings.Contains(string(output), "adopt inspection: ansible operation failed:") {
		t.Fatalf("expected isolated SSH inspection failure, got %v: %s", err, output)
	}
	state := filepath.Join(cache, "ultra-install")
	runtimeDir := filepath.Join(state, "runtime-"+asset.SHA)
	ready, err := os.ReadFile(filepath.Join(runtimeDir, "ready"))
	if err != nil || string(ready) != asset.SHA {
		t.Fatalf("pinned runtime was not committed: %v", err)
	}
	for _, path := range []string{runtimeDir, filepath.Join(runtimeDir, "venv")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm()&0077 != 0 {
			t.Fatalf("runtime directory is not private: %s (%v)", path, err)
		}
	}
	info, err := os.Stat(filepath.Join(runtimeDir, "venv", "bin", "ansible-playbook"))
	if err != nil || info.Mode().Perm()&0111 == 0 {
		t.Fatalf("pinned executor missing: %v", err)
	}
	jobs, err := filepath.Glob(filepath.Join(state, "adopt-*", "inspect", "job.json"))
	if err != nil || len(jobs) != 1 {
		t.Fatalf("expected one read-only inspection job: %v %v", jobs, err)
	}
	job, err := os.ReadFile(jobs[0])
	if err != nil || !strings.Contains(string(job), `"operation":"inspect-bootstrap"`) {
		t.Fatalf("unexpected inspection job: %s (%v)", job, err)
	}
}
