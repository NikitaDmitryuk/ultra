package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type autoFixtureTransport func(*http.Request) (*http.Response, error)

func (f autoFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAutoStableVersionRefusesDowngradeAndPrerelease(t *testing.T) {
	for _, tc := range []struct {
		next, current string
		want          bool
	}{
		{"v2.5.0", "v2.4.6", true}, {"v2.4.6", "v2.4.6", false}, {"v2.4.5", "v2.4.6", false}, {"v2.5.0-rc.1", "v2.4.6", false}, {"latest", "v2.4.6", false}, {"v2.4.10", "v2.4.9", true},
	} {
		if got := versionGreater(tc.next, tc.current); got != tc.want {
			t.Fatalf("%s > %s got %v", tc.next, tc.current, got)
		}
	}
}

func TestAutoReleaseRequiresCIForExactTaggedCommit(t *testing.T) {
	commit := strings.Repeat("a", 40)
	for _, tc := range []struct {
		tagSHA, conclusion, app, name string
		want                          bool
	}{
		{commit, "success", "github-actions", "Lint, test, build", true},
		{strings.Repeat("b", 40), "success", "github-actions", "Lint, test, build", false},
		{commit, "failure", "github-actions", "Lint, test, build", false},
		{commit, "success", "other-app", "Lint, test, build", false},
		{commit, "success", "github-actions", "Other", false},
	} {
		client := &http.Client{Transport: autoFixtureTransport(func(r *http.Request) (*http.Response, error) {
			body := `{"object":{"type":"commit","sha":"` + tc.tagSHA + `"}}`
			if strings.Contains(r.URL.Path, "check-runs") {
				body = `{"total_count":1,"check_runs":[{"name":"` + tc.name + `","head_sha":"` + commit + `","status":"completed","conclusion":"` + tc.conclusion + `","app":{"slug":"` + tc.app + `"}}]}`
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		})}
		got := verifyGithubCI(context.Background(), client, "example/project", "v2.5.0", commit, []string{"Lint, test, build"}) == nil
		if got != tc.want {
			t.Fatalf("CI contract %#v got %v", tc, got)
		}
	}
}

func TestAutoDownloadBoundsSizeAndOrigins(t *testing.T) {
	client := &http.Client{Transport: autoFixtureTransport(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("oversize")), Header: make(http.Header)}, nil
	})}
	destination := filepath.Join(t.TempDir(), "asset")
	if downloadAutoAsset(context.Background(), client, "https://example.com/file", destination, 4) == nil {
		t.Fatal("non-GitHub asset origin accepted")
	}
	if downloadAutoAsset(context.Background(), client, "https://github.com/example/file", destination, 4) == nil {
		t.Fatal("oversized asset accepted")
	}
}

func TestAutoHandoffRunsTargetInstallerAndRejectsChangedArtifact(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "target-role-sentinel")
	names := []string{"ultra-relay-linux-amd64", "ultra-relay-linux-arm64", "ultra-bot-linux-amd64", "ultra-bot-linux-arm64", "ultra-client-linux-amd64", "ultra-client-linux-arm64", "ultra-recovery.tar.gz", "ultra-install-linux-amd64", "ultra-install-linux-arm64", "ultra-ansible.tar.gz", "ultra-ansible-runtime-linux-amd64.tar.gz", "ultra-ansible-runtime-linux-arm64.tar.gz", "mobile-bootstrap.sh", "checksums.txt"}
	var assets []map[string]any
	for _, name := range names {
		data := []byte(name)
		if name == "ultra-install-linux-"+runtime.GOARCH {
			data = []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + marker + "'\nmkdir -p '" + dir + "/operation-v9.0.0/commit'\nprintf '%s' '{\"state\":\"succeeded\",\"result\":{\"verified\":true,\"version\":\"v9.0.0\"}}' > '" + dir + "/operation-v9.0.0/commit/receipt.json'\n")
		}
		sum := sha256.Sum256(data)
		assets = append(assets, map[string]any{"name": name, "size": len(data), "sha256": hex.EncodeToString(sum[:])})
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := json.Marshal(map[string]any{"schema_version": 1, "version": "v9.0.0", "source_commit": strings.Repeat("a", 40), "database_schema_min": 24, "database_schema_max": 25, "capabilities": []string{"service-access-v1", "provider-pool-quota-v1", "lifecycle-gate-v1", "ansible-deploy-v1"}, "assets": assets})
	if err := os.WriteFile(filepath.Join(dir, "release-manifest.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "canonical.config")
	if err := os.WriteFile(config, []byte("BRIDGE=192.0.2.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	policy := autoUpgradePolicy{ConfigFile: config, OperationLockDirectory: dir, Python: "/usr/bin/python3", Ansible: "/old/runtime/ansible-playbook"}
	if err := handoffAutoUpgrade(context.Background(), policy, dir, "v9.0.0"); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal("signed target installer did not run")
	}
	if !strings.Contains(string(args), "upgrade\n--config\n"+filepath.Join(dir, "operation-v9.0.0", "install.config")) || !strings.Contains(string(args), dir) || strings.Contains(string(args), "/old/runtime") {
		t.Fatalf("wrong target handoff: %s", args)
	}
	handed, manualErr := handoffManualUpgrade(context.Background(), &installplan.InstallPlan{}, dir, []string{"--config", config, "--release-dir", dir})
	if !handed || manualErr != nil {
		t.Fatalf("manual CLI did not enter target embedded bundle: %v %v", handed, manualErr)
	}
	if err = os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "ultra-install-linux-"+runtime.GOARCH), []byte("changed"), 0700); err != nil {
		t.Fatal(err)
	}
	if handoffAutoUpgrade(context.Background(), policy, dir, "v9.0.0") == nil {
		t.Fatal("modified target installer executed")
	}
	if _, err = os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("target script ran after failed hash check")
	}
}

func TestPublishedCandidateWithoutCommitStillResumes(t *testing.T) {
	dir := t.TempDir()
	job := filepath.Join(dir, "operation-v9.0.0")
	if err := os.MkdirAll(filepath.Join(job, "activate"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"install.config": "BRIDGE=192.0.2.1", "activate/job.json": "{}", "published.json": `{"version":"v9.0.0"}`} {
		if err := os.WriteFile(filepath.Join(job, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	policy := autoUpgradePolicy{OperationLockDirectory: dir, StateDirectory: dir}
	pending, err := pendingAutoUpgradeVersions(policy)
	if err != nil || len(pending) != 1 || pending[0] != "v9.0.0" {
		t.Fatalf("published candidate skipped: %v %v", pending, err)
	}
	if err = os.Mkdir(filepath.Join(job, "commit"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(job, "commit", "receipt.json"), []byte(`{"state":"succeeded","result":{"verified":true,"version":"v9.0.0"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	pending, err = pendingAutoUpgradeVersions(policy)
	if err != nil || len(pending) != 0 {
		t.Fatalf("accepted candidate repeated: %v %v", pending, err)
	}
}
