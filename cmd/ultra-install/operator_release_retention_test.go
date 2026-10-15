package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func retentionReleaseFixture(t *testing.T, cache, tag string, files map[string][]byte) string {
	t.Helper()
	path := filepath.Join(cache, "release-"+tag)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	makeReleaseTreeRemovable(t, path)
	for name, content := range files {
		if name == "release-manifest.json" {
			var manifest map[string]any
			if err := json.Unmarshal(content, &manifest); err != nil {
				t.Fatal(err)
			}
			manifest["version"] = tag
			var err error
			content, err = json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(path, name), content, 0400); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(path, 0500); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOperatorReleaseCachePrunesOnlyVerifiedStaleBundles(t *testing.T) {
	files, _, signer := githubFixture(t)
	root := githubPrivateStage(t)
	cache := filepath.Join(root, "releases")
	if err := os.Mkdir(cache, 0700); err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{}
	for _, tag := range []string{"v1.0.0", "v2.0.0", "v3.0.0", "v4.0.0", "v5.0.0", "v6.0.0", "v7.0.0", "v8.0.0", "v9.0.0"} {
		paths[tag] = retentionReleaseFixture(t, cache, tag, files)
	}
	// The fallback/current tags and an in-flight asset reference all survive.
	job := filepath.Join(root, "upgrade-live")
	if err := os.Mkdir(job, 0700); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"variables": map[string]any{"ultra_relay_source": filepath.Join(paths["v3.0.0"], "ultra-relay-linux-amd64")}})
	if err := os.WriteFile(filepath.Join(job, "request.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	// Hash modification is rejected even after restoring published modes.
	modified := filepath.Join(paths["v4.0.0"], "ultra-relay-linux-amd64")
	if err := os.Chmod(modified, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(modified, []byte("modified"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(modified, 0400); err != nil {
		t.Fatal(err)
	}
	// Foreign/unknown files, symlinks, mutable modes, and bad signatures survive.
	if err := os.Chmod(paths["v5.0.0"], 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths["v5.0.0"], "unknown"), []byte("unknown"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths["v5.0.0"], 0500); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths["v6.0.0"], 0700); err != nil {
		t.Fatal(err)
	}
	asset := filepath.Join(paths["v6.0.0"], "ultra-relay-linux-amd64")
	if err := os.Remove(asset); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(modified, asset); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths["v6.0.0"], 0500); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(paths["v7.0.0"], "ultra-relay-linux-amd64"), 0600); err != nil {
		t.Fatal(err)
	}
	signature := filepath.Join(paths["v8.0.0"], "checksums.txt.minisig")
	if err := os.Chmod(signature, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signature, []byte("bad"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(signature, 0400); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(cache, "release-v0.0.0-preview")
	if err := os.Mkdir(unknown, 0700); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(cache, "release-v0.1.0")
	if err := os.Symlink(paths["v9.0.0"], linked); err != nil {
		t.Fatal(err)
	}
	if err := pruneVerifiedOperatorReleaseCache(cache, root, "trusted-key", signer, "v1.0.0", "v2.0.0"); err != nil {
		t.Fatal(err)
	}
	for tag, path := range paths {
		_, err := os.Lstat(path)
		if tag == "v9.0.0" {
			if !os.IsNotExist(err) {
				t.Fatalf("verified stale bundle remains: %v", err)
			}
		} else if err != nil {
			t.Fatalf("protected %s removed: %v", tag, err)
		}
	}
	for _, path := range []string{unknown, linked, filepath.Join(job, "request.json")} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("unknown or metadata entry removed: %v", err)
		}
	}
	// The helper rechecks both signed metadata inputs.
	calls, err := os.ReadFile(os.Getenv("MINISIGN_TEST_LOG"))
	if err != nil || len(calls) == 0 {
		t.Fatalf("signature verifier not invoked: %v", err)
	}
}

func TestOperatorReleaseCacheInvalidLiveMetadataPreventsDeletion(t *testing.T) {
	for _, contents := range []string{"{invalid", "null", "[]"} {
		t.Run(contents, func(t *testing.T) {
			files, _, signer := githubFixture(t)
			root := githubPrivateStage(t)
			cache := filepath.Join(root, "releases")
			if err := os.Mkdir(cache, 0700); err != nil {
				t.Fatal(err)
			}
			stale := retentionReleaseFixture(t, cache, "v1.0.0", files)
			job := filepath.Join(root, "upgrade-live")
			if err := os.Mkdir(job, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(job, "request.json"), []byte(contents), 0600); err != nil {
				t.Fatal(err)
			}
			if err := pruneVerifiedOperatorReleaseCache(cache, root, "trusted-key", signer, "v2.0.0"); err == nil {
				t.Fatal("invalid live metadata accepted")
			}
			if _, err := os.Stat(stale); err != nil {
				t.Fatalf("deleted stale bundle despite unknown references: %v", err)
			}
		})
	}
}

func TestOperatorReleaseCacheRequiresExplicitTrustedIdentity(t *testing.T) {
	root := githubPrivateStage(t)
	for _, keep := range [][]string{nil, {"latest"}, {"v2.0.0", ""}} {
		if err := pruneVerifiedOperatorReleaseCache(root, root, "trusted-key", "minisign", keep...); err == nil {
			t.Fatal("invalid keep identity accepted")
		}
	}
	if err := pruneVerifiedOperatorReleaseCache(root, root, "", "minisign", "v2.0.0"); err == nil {
		t.Fatal("missing trusted key accepted")
	}
}

func TestOperatorReleasePinProtectsDifferentOperatorRoot(t *testing.T) {
	files, _, signer := githubFixture(t)
	root := githubPrivateStage(t)
	cache := filepath.Join(root, "releases")
	if err := os.Mkdir(cache, 0700); err != nil {
		t.Fatal(err)
	}
	release := retentionReleaseFixture(t, cache, "v1.0.0", files)
	opA := filepath.Join(root, "custom", "operations", "upgrade-v1")
	opB := filepath.Join(root, "other", "operations", "upgrade-v2")
	for _, path := range []string{opA, opB} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := pinOperatorRelease(cache, opA, release); err != nil {
		t.Fatal(err)
	}
	if err := pruneVerifiedOperatorReleaseCache(cache, filepath.Dir(opB), "trusted-key", signer, "v2.0.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(release); err != nil {
		t.Fatalf("release referenced from another operator root was removed: %v", err)
	}
	if err := unpinOperatorReleaseReferences(cache, opA); err != nil {
		t.Fatal(err)
	}
	if err := pruneVerifiedOperatorReleaseCache(cache, filepath.Dir(opB), "trusted-key", signer, "v2.0.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(release); !os.IsNotExist(err) {
		t.Fatalf("unreferenced stale release was not removed: %v", err)
	}
}

func TestOperatorReleasePinPublicationIsAtomicAndIdempotent(t *testing.T) {
	root := githubPrivateStage(t)
	cache := filepath.Join(root, "releases")
	if err := os.Mkdir(cache, 0700); err != nil {
		t.Fatal(err)
	}
	release := filepath.Join(cache, "release-v1.0.0")
	if err := os.Mkdir(release, 0700); err != nil {
		t.Fatal(err)
	}
	operation := filepath.Join(root, "operation")
	if err := os.Mkdir(operation, 0700); err != nil {
		t.Fatal(err)
	}
	path, expected, err := operatorReleasePinPath(cache, operation, release)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := pinOperatorRelease(cache, operation, release); err != nil {
			t.Fatalf("pin attempt %d: %v", i+1, err)
		}
		actual, err := readOperatorReleasePin(path)
		if err != nil {
			t.Fatalf("read published pin after attempt %d: %v", i+1, err)
		}
		if actual != expected {
			t.Fatalf("published pin mismatch: got %#v, want %#v", actual, expected)
		}
	}
	entries, err := os.ReadDir(cache)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), operatorReleasePinTempPrefix) {
			t.Fatalf("temporary pin file left behind: %s", entry.Name())
		}
	}
	if err := os.WriteFile(filepath.Join(cache, operatorReleasePinTempPrefix+"abandoned"), []byte(`{"partial"`), 0600); err != nil {
		t.Fatal(err)
	}
	pins, err := operatorReleasePinsLocked(cache)
	if err != nil || len(pins) != 1 {
		t.Fatalf("abandoned temp file affected published pin scan: pins=%d err=%v", len(pins), err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("pin mode = %04o, want 0600", info.Mode().Perm())
	}
}

func TestOperatorReleaseCachePreservesHardlinkedAssets(t *testing.T) {
	files, _, signer := githubFixture(t)
	root := githubPrivateStage(t)
	cache := githubPrivateStage(t)
	stale := retentionReleaseFixture(t, cache, "v1.0.0", files)
	asset := filepath.Join(stale, "ultra-relay-linux-amd64")
	if err := os.Link(asset, filepath.Join(root, "linked-asset")); err != nil {
		t.Fatal(err)
	}
	if err := pruneVerifiedOperatorReleaseCache(cache, root, "trusted-key", signer, "v2.0.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); err != nil {
		t.Fatalf("hardlinked release removed: %v", err)
	}
}

func TestOperatorReleaseCacheLeaseBeforeRequestMetadata(t *testing.T) {
	for _, kind := range []string{"fetch", "snapshot"} {
		t.Run(kind, func(t *testing.T) {
			files, inventory, signer := githubFixture(t)
			root := githubPrivateStage(t)
			cache := filepath.Join(root, "releases")
			if err := os.Mkdir(cache, 0700); err != nil {
				t.Fatal(err)
			}
			var lease VerifiedGitHubRelease
			var err error
			if kind == "fetch" {
				var requests []string
				lease, err = FetchVerifiedGitHubRelease(context.Background(), GitHubReleaseOptions{PublicKey: "trusted-key", StagingBase: cache, MinisignPath: signer, Client: githubFixtureClient(files, inventory, &requests)})
			} else {
				source := githubPrivateStage(t)
				for name, content := range files {
					if err := os.WriteFile(filepath.Join(source, name), content, 0600); err != nil {
						t.Fatal(err)
					}
				}
				lease, err = snapshotSignedAutomationRelease(source, "trusted-key", cache, signer)
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = lease.Close() })
			makeReleaseTreeRemovable(t, cache)
			prune := func() {
				t.Helper()
				if err := pruneVerifiedOperatorReleaseCache(cache, root, "trusted-key", signer, "v9.0.0"); err != nil {
					t.Fatal(err)
				}
			}
			// Actual subprocess opens an independent shared flock while parent holds it.
			child := exec.Command(os.Args[0], "-test.run=^TestReleaseCacheLeaseChildHelper$")
			child.Env = []string{"ULTRA_TEST_LEASE_DIRECTORY=" + lease.Directory, "ULTRA_TEST_LEASE_TAG=" + lease.Tag}
			if output, err := child.CombinedOutput(); err != nil {
				t.Fatalf("child handoff: %v: %s", err, output)
			}
			second, err := AcquireVerifiedGitHubRelease(lease.Directory, lease.Tag)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = second.Close() })
			prune()
			if _, err := os.Stat(lease.Directory); err != nil {
				t.Fatalf("leased bundle pruned before request.json: %v", err)
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			prune()
			if _, err := os.Stat(lease.Directory); err != nil {
				t.Fatalf("child lease did not protect bundle: %v", err)
			}
			if err := second.Close(); err != nil {
				t.Fatal(err)
			}
			if err := second.Close(); err != nil {
				t.Fatalf("Close not idempotent: %v", err)
			}
			prune()
			if _, err := os.Lstat(lease.Directory); !os.IsNotExist(err) {
				t.Fatalf("closed bundle not pruned: %v", err)
			}
			entries, err := os.ReadDir(cache)
			if err != nil || len(entries) != 0 {
				t.Fatalf("lock artifacts leaked: %v, %v", entries, err)
			}
		})
	}
}

func TestReleaseCacheLeaseChildHelper(t *testing.T) {
	directory := os.Getenv("ULTRA_TEST_LEASE_DIRECTORY")
	if directory == "" {
		return
	}
	lease, err := AcquireVerifiedGitHubRelease(directory, os.Getenv("ULTRA_TEST_LEASE_TAG"))
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestGitHubReleaseCacheFailureReleasesLease(t *testing.T) {
	files, inventory, signer := githubFixture(t)
	root := githubPrivateStage(t)
	cache := filepath.Join(root, "releases")
	var requests []string
	options := GitHubReleaseOptions{PublicKey: "trusted-key", StagingBase: cache, MinisignPath: signer, Client: githubFixtureClient(files, inventory, &requests)}
	lease, err := FetchVerifiedGitHubRelease(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lease.Close() })
	makeReleaseTreeRemovable(t, cache)
	files["release-manifest.json"] = []byte(strings.Replace(string(files["release-manifest.json"]), strings.Repeat("a", 40), strings.Repeat("b", 40), 1))
	if failed, err := FetchVerifiedGitHubRelease(context.Background(), options); err == nil {
		_ = failed.Close()
		t.Fatal("changed metadata accepted")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pruneVerifiedOperatorReleaseCache(cache, root, "trusted-key", signer, "v9.0.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(lease.Directory); !os.IsNotExist(err) {
		t.Fatalf("error path leaked lease: %v", err)
	}
}

func TestReleaseCacheLeaseRefusesExclusivePruningLock(t *testing.T) {
	files, _, _ := githubFixture(t)
	cache := githubPrivateStage(t)
	path := retentionReleaseFixture(t, cache, "v1.0.0", files)
	exclusive, err := lockReleaseDirectory(path, syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := exclusive.Close(); err != nil {
			t.Errorf("close exclusive release lock: %v", err)
		}
	})
	if lease, err := AcquireVerifiedGitHubRelease(path, "v1.0.0"); err == nil {
		_ = lease.Close()
		t.Fatal("leased an entry undergoing pruning")
	}
	// A failed acquisition must release the root gate as well.
	gate, err := lockReleaseDirectory(cache, syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotCollisionFailureReleasesLease(t *testing.T) {
	files, _, signer := githubFixture(t)
	root := githubPrivateStage(t)
	cache := filepath.Join(root, "releases")
	if err := os.Mkdir(cache, 0700); err != nil {
		t.Fatal(err)
	}
	path := retentionReleaseFixture(t, cache, "v2.5.0", files)
	source := githubPrivateStage(t)
	files["release-manifest.json"] = []byte(strings.Replace(string(files["release-manifest.json"]), strings.Repeat("a", 40), strings.Repeat("b", 40), 1))
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(source, name), contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if lease, err := snapshotSignedAutomationRelease(source, "trusted-key", cache, signer); err == nil {
		_ = lease.Close()
		t.Fatal("different bundle accepted")
	}
	if err := pruneVerifiedOperatorReleaseCache(cache, root, "trusted-key", signer, "v9.0.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("collision failure leaked lease: %v", err)
	}
	// Republish the same tag on a new inode; no stale lock artifact may protect it.
	lease, err := snapshotSignedAutomationRelease(source, "trusted-key", cache, signer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lease.Close() })
	makeReleaseTreeRemovable(t, cache)
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pruneVerifiedOperatorReleaseCache(cache, root, "trusted-key", signer, "v9.0.0"); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(cache)
	if err != nil || len(entries) != 0 {
		t.Fatalf("republished tag or lock leaked: %v, %v", entries, err)
	}
}
