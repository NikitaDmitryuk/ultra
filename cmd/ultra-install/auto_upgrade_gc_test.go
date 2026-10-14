package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

func TestAutoRetentionKeepsFleetLeaseUntilDownloadFailure(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python unavailable")
	}
	root := t.TempDir()
	lock := filepath.Join(root, "fleet")
	state := filepath.Join(lock, "downloads")
	if err = os.MkdirAll(state, 0700); err != nil {
		t.Fatal(err)
	}
	playbook := filepath.Join(root, "playbook")
	stub := fmt.Sprintf("#!%s\nimport json,pathlib,sys\nv=json.loads((pathlib.Path(sys.argv[-1][1:]).parent/'variables.json').read_text())\np=pathlib.Path(v['ultra_result_file'])\np.write_text(json.dumps({'verified':True}))\np.chmod(0o600)\n", python)
	if err = os.WriteFile(playbook, []byte(stub), 0700); err != nil {
		t.Fatal(err)
	}
	var observed atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, release, leaseErr := deployansible.WithOperationLock(context.Background(), lock)
		if leaseErr == nil {
			release()
		} else {
			observed.Store(true)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	fixtureURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: autoFixtureTransport(func(request *http.Request) (*http.Response, error) {
		clone := request.Clone(request.Context())
		address := *request.URL
		address.Scheme, address.Host = fixtureURL.Scheme, fixtureURL.Host
		clone.URL = &address
		return server.Client().Do(clone)
	})}
	policy := autoUpgradePolicy{OperationLockDirectory: lock, StateDirectory: state, Python: python, Ansible: playbook}
	releaseInfo := githubStableRelease{Tag: "v9.0.0"}
	releaseInfo.Assets = append(releaseInfo.Assets, struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	}{Name: "release-manifest.json", URL: "https://github.com/example/project/releases/download/v9.0.0/release-manifest.json"})
	_, err = prepareAutoReleaseWithRetention(context.Background(), client, policy, releaseInfo)
	if err == nil || !strings.Contains(err.Error(), "auto_signed_manifest_unavailable") || !observed.Load() {
		t.Fatalf("download did not retain lease: %v, observed=%v", err, observed.Load())
	}
	_, release, err := deployansible.WithOperationLock(context.Background(), lock)
	if err != nil {
		t.Fatal("failed preflight leaked lease", err)
	}
	release()
}

func TestAutoCommitReceiptUsesActivationGeneration(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "activate"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "activate", "job.json"), []byte(`{"attempt":2}`), 0600); err != nil {
		t.Fatal(err)
	}
	path, err := autoUpgradeCommitDirectory(directory)
	if err != nil || path != filepath.Join(directory, "commit-generation-2") {
		t.Fatal(path, err)
	}
}
