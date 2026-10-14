package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type githubFixtureTransport func(*http.Request) (*http.Response, error)

func githubPrivateStage(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func makeReleaseTreeRemovable(t *testing.T, directory string) {
	t.Helper()
	t.Cleanup(func() {
		var paths []string
		_ = filepath.WalkDir(directory, func(path string, _ os.DirEntry, err error) error {
			if err == nil {
				paths = append(paths, path)
			}
			return nil
		})
		for i := len(paths) - 1; i >= 0; i-- {
			info, err := os.Lstat(paths[i])
			if err == nil && info.IsDir() {
				_ = os.Chmod(paths[i], 0700)
			}
		}
	})
}

func (f githubFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func githubFixture(t *testing.T) (map[string][]byte, githubReleaseInventory, string) {
	t.Helper()
	files := map[string][]byte{}
	names := []string{"ultra-relay-linux-amd64", "ultra-relay-linux-arm64", "ultra-bot-linux-amd64", "ultra-bot-linux-arm64", "ultra-client-linux-amd64", "ultra-client-linux-arm64", "ultra-recovery.tar.gz", "ultra-install-linux-amd64", "ultra-install-linux-arm64", "ultra-ansible.tar.gz", "ultra-ansible-runtime-linux-amd64.tar.gz", "ultra-ansible-runtime-linux-arm64.tar.gz", "mobile-bootstrap.sh"}
	var sums strings.Builder
	var rows []map[string]any
	for _, name := range names {
		content := []byte(name)
		files[name] = content
		digest := sha256.Sum256(content)
		hash := hex.EncodeToString(digest[:])
		sums.WriteString(hash + "  " + name + "\n")
		rows = append(rows, map[string]any{"name": name, "sha256": hash, "size": len(content)})
	}
	files["checksums.txt"] = []byte(sums.String())
	digest := sha256.Sum256(files["checksums.txt"])
	rows = append(rows, map[string]any{"name": "checksums.txt", "sha256": hex.EncodeToString(digest[:]), "size": len(files["checksums.txt"])})
	manifest := map[string]any{"schema_version": 1, "version": "v2.5.0", "source_commit": strings.Repeat("a", 40), "database_schema_min": 24, "database_schema_max": 25, "capabilities": []string{"service-access-v1", "provider-pool-quota-v1", "lifecycle-gate-v1", "ansible-deploy-v1"}, "assets": rows}
	files["release-manifest.json"], _ = json.Marshal(manifest)
	files["release-manifest.json.minisig"] = []byte("good")
	files["checksums.txt.minisig"] = []byte("good")
	inventory := githubReleaseInventory{Tag: "v2.5.0"}
	var sorted []string
	for name := range files {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)
	for _, name := range sorted {
		inventory.Assets = append(inventory.Assets, struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
			Size int64  `json:"size"`
		}{name, "https://github.com/" + githubReleaseRepository + "/releases/download/v2.5.0/" + name, int64(len(files[name]))})
	}
	bin := t.TempDir()
	signer := filepath.Join(bin, "minisign")
	script := `#!/bin/sh
[ "$#" = 6 ] && [ "$1" = -Vm ] && [ "$3" = -x ] && [ "$5" = -P ] && [ "$6" = trusted-key ] || exit 17
[ "$4" = "$2.minisig" ] || exit 18
[ "$(cat "$4")" = good ] || exit 19
printf '%s\n' "$2" >> "$MINISIGN_TEST_LOG"
`
	if err := os.WriteFile(signer, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MINISIGN_TEST_LOG", filepath.Join(bin, "calls"))
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	return files, inventory, signer
}
func githubFixtureClient(files map[string][]byte, inventory githubReleaseInventory, requests *[]string) *http.Client {
	return &http.Client{Transport: githubFixtureTransport(func(r *http.Request) (*http.Response, error) {
		*requests = append(*requests, r.URL.String())
		var raw []byte
		if r.URL.Hostname() == "api.github.com" {
			raw, _ = json.Marshal(inventory)
		} else {
			raw = files[filepath.Base(r.URL.Path)]
		}
		status := 200
		if raw == nil {
			status = 404
		}
		return &http.Response{StatusCode: status, ContentLength: int64(len(raw)), Body: io.NopCloser(strings.NewReader(string(raw))), Header: make(http.Header), Request: r}, nil
	})}
}
func TestGitHubReleaseStableLatestAndExplicitTag(t *testing.T) {
	for _, selector := range []string{"", "latest", "v2.5.0"} {
		t.Run("selector-"+selector, func(t *testing.T) {
			files, inventory, signer := githubFixture(t)
			var requests []string
			stage := githubPrivateStage(t)
			got, err := FetchVerifiedGitHubRelease(context.Background(), GitHubReleaseOptions{Selector: selector, PublicKey: "trusted-key", StagingBase: stage, Client: githubFixtureClient(files, inventory, &requests), MinisignPath: signer})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = got.Close() })
			if got.Tag != "v2.5.0" || filepath.Dir(got.Directory) != stage {
				t.Fatalf("invalid result: %#v", got)
			}
			endpoint := "/releases/latest"
			if selector == "v2.5.0" {
				endpoint = "/releases/tags/v2.5.0"
			}
			if !strings.HasSuffix(requests[0], endpoint) {
				t.Fatalf("wrong selector endpoint: %s", requests[0])
			}
			calls, err := os.ReadFile(os.Getenv("MINISIGN_TEST_LOG"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(calls), "\n") != 2 {
				t.Fatalf("expected both signatures verified: %s", calls)
			}
			for name := range files {
				info, err := os.Stat(filepath.Join(got.Directory, name))
				if err != nil || info.Mode().Perm() != 0400 {
					t.Fatalf("immutable %s: %v", name, err)
				}
			}
			if _, err = VerifySignedAutomationRelease(got.Directory, "trusted-key"); err != nil {
				t.Fatal(err)
			}
			if err = os.Chmod(filepath.Join(got.Directory, "ultra-relay-linux-amd64"), 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(got.Directory, "ultra-relay-linux-amd64"), []byte("corrupt"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = VerifySignedAutomationRelease(got.Directory, "trusted-key"); err == nil {
				t.Fatal("corrupted retained bundle accepted")
			}
			// Restore directory permission so testing cleanup can remove the immutable bundle.
			_ = os.Chmod(got.Directory, 0700)
		})
	}
}

func TestGitHubReleaseReusesValidatedImmutableTagCache(t *testing.T) {
	files, inventory, signer := githubFixture(t)
	stage := githubPrivateStage(t)
	var firstRequests []string
	first, err := FetchVerifiedGitHubRelease(context.Background(), GitHubReleaseOptions{
		Selector: "latest", PublicKey: "trusted-key", StagingBase: stage,
		Client: githubFixtureClient(files, inventory, &firstRequests), MinisignPath: signer,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	var retryRequests []string
	retry, err := FetchVerifiedGitHubRelease(context.Background(), GitHubReleaseOptions{
		Selector: "latest", PublicKey: "trusted-key", StagingBase: stage,
		Client: githubFixtureClient(files, inventory, &retryRequests), MinisignPath: signer,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = retry.Close() })
	if retry.Directory != first.Directory {
		t.Fatalf("same signed tag changed release path: %q != %q", retry.Directory, first.Directory)
	}
	makeReleaseTreeRemovable(t, stage)
	if len(retryRequests) != 5 || !strings.HasSuffix(retryRequests[0], "/releases/latest") {
		t.Fatalf("cache revalidation should resolve latest and fetch signed metadata: %#v", retryRequests)
	}
}

func TestGitHubReleaseRejectsChangedSignedContentsForCachedTag(t *testing.T) {
	files, inventory, signer := githubFixture(t)
	stage := githubPrivateStage(t)
	var requests []string
	first, err := FetchVerifiedGitHubRelease(context.Background(), GitHubReleaseOptions{
		Selector: "latest", PublicKey: "trusted-key", StagingBase: stage,
		Client: githubFixtureClient(files, inventory, &requests), MinisignPath: signer,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	files["release-manifest.json"] = []byte(strings.Replace(string(files["release-manifest.json"]), strings.Repeat("a", 40), strings.Repeat("b", 40), 1))
	requests = nil
	if _, err := FetchVerifiedGitHubRelease(context.Background(), GitHubReleaseOptions{
		Selector: "latest", PublicKey: "trusted-key", StagingBase: stage,
		Client: githubFixtureClient(files, inventory, &requests), MinisignPath: signer,
	}); err == nil {
		t.Fatal("changed signed contents for the cached tag were accepted")
	}
	makeReleaseTreeRemovable(t, stage)
}

func TestSnapshotSignedAutomationReleaseCopiesVerifiedBytes(t *testing.T) {
	files, _, _ := githubFixture(t)
	source := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(source, name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	stage := githubPrivateStage(t)
	got, err := SnapshotSignedAutomationRelease(source, "trusted-key", stage)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = got.Close() })
	if got.Tag != "v2.5.0" || filepath.Dir(got.Directory) != stage {
		t.Fatalf("unexpected snapshot: %#v", got)
	}
	makeReleaseTreeRemovable(t, stage)
	if err := os.WriteFile(filepath.Join(source, "ultra-relay-linux-amd64"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedAutomationRelease(got.Directory, "trusted-key"); err != nil {
		t.Fatalf("source mutation affected immutable snapshot: %v", err)
	}
}

func TestSnapshotSignedAutomationReleaseRejectsSymlinks(t *testing.T) {
	files, _, _ := githubFixture(t)
	source := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(source, name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	asset := filepath.Join(source, "ultra-relay-linux-amd64")
	if err := os.Remove(asset); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", asset); err != nil {
		t.Fatal(err)
	}
	if _, err := SnapshotSignedAutomationRelease(source, "trusted-key", githubPrivateStage(t)); err == nil {
		t.Fatal("symlinked release asset accepted")
	}
}

func TestGitHubReleaseRejectsPrereleaseSelector(t *testing.T) {
	files, inventory, signer := githubFixture(t)
	var requests []string
	_, err := FetchVerifiedGitHubRelease(context.Background(), GitHubReleaseOptions{
		Selector: "v2.5.0-rc.1", PublicKey: "trusted-key", StagingBase: githubPrivateStage(t),
		Client: githubFixtureClient(files, inventory, &requests), MinisignPath: signer,
	})
	if err == nil || len(requests) != 0 {
		t.Fatalf("prerelease selector accepted or fetched: err=%v requests=%#v", err, requests)
	}
}

func TestGitHubReleaseRejectsInvalidBundles(t *testing.T) {
	cases := []string{"bad-manifest-signature", "bad-checksum-signature", "corrupt-asset", "missing-signature", "duplicate-asset", "unsafe-name", "unsafe-url", "wrong-tag-url", "extra-asset", "latest-prerelease", "draft", "tag-mismatch", "manifest-tag-mismatch", "checksum-inventory-mismatch", "invalid-source-commit", "invalid-schema-range", "no-ansible-capability", "unexpected-manifest-asset"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			files, inventory, signer := githubFixture(t)
			selector := "latest"
			switch name {
			case "bad-manifest-signature":
				files["release-manifest.json.minisig"] = []byte("evil")
			case "bad-checksum-signature":
				files["checksums.txt.minisig"] = []byte("evil")
			case "corrupt-asset":
				files["ultra-relay-linux-amd64"][0] = '!'
			case "missing-signature":
				for i, a := range inventory.Assets {
					if a.Name == "checksums.txt.minisig" {
						inventory.Assets = append(inventory.Assets[:i], inventory.Assets[i+1:]...)
						break
					}
				}
			case "duplicate-asset":
				inventory.Assets = append(inventory.Assets, inventory.Assets[0])
			case "unsafe-name":
				inventory.Assets[0].Name = "../bad"
			case "unsafe-url":
				inventory.Assets[0].URL = "https://example.com/asset"
			case "wrong-tag-url":
				inventory.Assets[0].URL = strings.ReplaceAll(inventory.Assets[0].URL, "v2.5.0", "v2.4.0")
			case "extra-asset":
				a := inventory.Assets[0]
				a.Name = "extra"
				a.URL = "https://github.com/" + githubReleaseRepository + "/releases/download/v2.5.0/extra"
				inventory.Assets = append(inventory.Assets, a)
			case "latest-prerelease":
				inventory.Prerelease = true
			case "draft":
				inventory.Draft = true
			case "tag-mismatch":
				selector = "v2.4.0"
			case "manifest-tag-mismatch":
				files["release-manifest.json"] = []byte(strings.ReplaceAll(string(files["release-manifest.json"]), "v2.5.0", "v2.4.0"))
			case "no-ansible-capability", "unexpected-manifest-asset":
				var manifest map[string]any
				_ = json.Unmarshal(files["release-manifest.json"], &manifest)
				if name == "no-ansible-capability" {
					manifest["capabilities"] = []string{"service-access-v1", "provider-pool-quota-v1", "lifecycle-gate-v1"}
				} else {
					// Replace one legitimate asset, preserving the asset count to
					// exercise exact membership rather than just cardinality.
					manifest["assets"].([]any)[0].(map[string]any)["name"] = "unexpected-runtime.tar.gz"
				}
				files["release-manifest.json"], _ = json.Marshal(manifest)
			case "invalid-source-commit", "invalid-schema-range":
				var manifest map[string]any
				_ = json.Unmarshal(files["release-manifest.json"], &manifest)
				if name == "invalid-source-commit" {
					manifest["source_commit"] = "unknown"
				} else {
					manifest["database_schema_max"] = 23
				}
				files["release-manifest.json"], _ = json.Marshal(manifest)
			case "checksum-inventory-mismatch":
				files["checksums.txt"] = []byte(strings.ReplaceAll(string(files["checksums.txt"]), "ultra-relay-linux-amd64", "ultra-relay-linux-amd65"))
				digest := sha256.Sum256(files["checksums.txt"])
				var m map[string]any
				_ = json.Unmarshal(files["release-manifest.json"], &m)
				for _, r := range m["assets"].([]any) {
					row := r.(map[string]any)
					if row["name"] == "checksums.txt" {
						row["sha256"] = hex.EncodeToString(digest[:])
					}
				}
				files["release-manifest.json"], _ = json.Marshal(m)
			}
			// Model the API size honestly when metadata has changed.
			for i, a := range inventory.Assets {
				if content, ok := files[a.Name]; ok {
					inventory.Assets[i].Size = int64(len(content))
				}
			}
			var requests []string
			stage := githubPrivateStage(t)
			_, err := FetchVerifiedGitHubRelease(context.Background(), GitHubReleaseOptions{Selector: selector, PublicKey: "trusted-key", StagingBase: stage, Client: githubFixtureClient(files, inventory, &requests), MinisignPath: signer})
			if err == nil {
				t.Fatal("invalid release accepted")
			}
			entries, e := os.ReadDir(stage)
			if e != nil || len(entries) != 0 {
				t.Fatalf("failed release was published or leaked: %v %v", entries, e)
			}
			if strings.Contains(name, "signature") {
				for _, r := range requests {
					if strings.Contains(r, "ultra-relay-linux") {
						t.Fatal("payload requested before signature verification")
					}
				}
			}
		})
	}
}
func TestGitHubReleaseFailClosedPrerequisites(t *testing.T) {
	files, inventory, signer := githubFixture(t)
	var requests []string
	options := GitHubReleaseOptions{PublicKey: "trusted-key", StagingBase: githubPrivateStage(t), Client: githubFixtureClient(files, inventory, &requests), MinisignPath: signer}
	options.PublicKey = ""
	if _, err := FetchVerifiedGitHubRelease(context.Background(), options); err == nil {
		t.Fatal("missing key accepted")
	}
	options.PublicKey = "trusted-key"
	options.MinisignPath = filepath.Join(t.TempDir(), "absent")
	if _, err := FetchVerifiedGitHubRelease(context.Background(), options); err == nil {
		t.Fatal("missing minisign accepted")
	}
	if len(requests) != 0 {
		t.Fatal("network used before prerequisites")
	}
	if _, err := VerifySignedAutomationRelease(t.TempDir(), ""); err == nil {
		t.Fatal("unsigned local directory accepted")
	}
}
func TestGitHubReleaseDownloadBoundsAndRedirects(t *testing.T) {
	for _, name := range []string{"unsafe-redirect", "oversized-body", "oversized-header"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			client := githubBoundedClient(&http.Client{Transport: githubFixtureTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				response := &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("12345")), ContentLength: -1, Request: r}
				if name == "unsafe-redirect" {
					response.StatusCode = 302
					response.Header.Set("Location", "http://example.com/payload")
				}
				if name == "oversized-header" {
					response.ContentLength = 999
				}
				return response, nil
			})})
			if _, err := githubDownload(context.Background(), client, "https://github.com/test", 4); err == nil {
				t.Fatal("unsafe download accepted")
			}
			if calls != 1 {
				t.Fatalf("unexpected requests: %d", calls)
			}
		})
	}
}

func TestGitHubReleaseRejectsUnsafeStagingBase(t *testing.T) {
	for _, mode := range []string{"public", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			files, inventory, signer := githubFixture(t)
			base := t.TempDir()
			stage := filepath.Join(base, "stage")
			if mode == "symlink" {
				if err := os.Symlink(t.TempDir(), stage); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(stage, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(stage, 0755); err != nil {
					t.Fatal(err)
				}
			}
			var requests []string
			_, err := FetchVerifiedGitHubRelease(context.Background(), GitHubReleaseOptions{PublicKey: "trusted-key", StagingBase: stage, Client: githubFixtureClient(files, inventory, &requests), MinisignPath: signer})
			if err == nil {
				t.Fatal("unsafe staging base accepted")
			}
		})
	}
}

func TestPublishLeasedReleaseRejectsManifestCollisionUnderCacheGate(t *testing.T) {
	cache := githubPrivateStage(t)
	candidate := filepath.Join(cache, ".release-pending-test")
	published := filepath.Join(cache, "release-v1.2.3")
	t.Cleanup(func() {
		_ = os.Chmod(candidate, 0700)
		_ = os.Chmod(published, 0700)
	})
	for path, manifest := range map[string]string{candidate: `{"version":"v1.2.3","source_commit":"candidate"}`, published: `{"version":"v1.2.3","source_commit":"winner"}`} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "release-manifest.json"), []byte(manifest), 0400); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0500); err != nil {
			t.Fatal(err)
		}
	}
	if lease, renamed, err := publishLeasedRelease(candidate, published, "v1.2.3"); err == nil {
		_ = lease.Close()
		t.Fatalf("different winner manifest accepted (renamed=%v)", renamed)
	}
	if _, err := os.Stat(candidate); err != nil {
		t.Fatalf("candidate was consumed on collision: %v", err)
	}
	if _, err := os.Stat(published); err != nil {
		t.Fatalf("winner bundle changed on collision: %v", err)
	}
}
