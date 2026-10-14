package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const githubReleaseRepository = "NikitaDmitryuk/ultra"
const githubMetadataLimit int64 = 2 << 20
const githubAssetLimit int64 = 512 << 20
const githubBundleLimit int64 = 2 << 30
const upgradeMinisignPathEnv = "ULTRA_UPGRADE_MINISIGN_PATH"

var githubAssetName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
var githubSHA = regexp.MustCompile(`^[a-f0-9]{64}$`)
var stableReleaseTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

type GitHubReleaseOptions struct {
	Selector     string
	PublicKey    string
	StagingBase  string
	Client       *http.Client
	MinisignPath string
}

// VerifiedGitHubRelease owns a shared bundle lease until Close. Copies share the
// lease; Close is idempotent. Retain it until asset users finish or durable
// operator metadata protects the bundle.
type VerifiedGitHubRelease struct {
	Tag, Directory string
	lease          *releaseBundleLease
}
type releaseBundleLease struct {
	file *os.File
	once sync.Once
	err  error
}

func (release VerifiedGitHubRelease) Close() error {
	if release.lease == nil {
		return nil
	}
	release.lease.once.Do(func() { release.lease.err = release.lease.file.Close() })
	return release.lease.err
}

// AcquireVerifiedGitHubRelease leases a cache entry for child handoff. It does
// not authenticate contents: reverify signatures while holding the lease.
// Independent shared leases coexist across processes.
func AcquireVerifiedGitHubRelease(directory, tag string) (VerifiedGitHubRelease, error) {
	var result VerifiedGitHubRelease
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return result, err
	}
	if !stableReleaseTag.MatchString(tag) || filepath.Base(absolute) != "release-"+tag {
		return result, errors.New("invalid release cache lease identity")
	}
	gate, err := lockReleaseCacheGate(filepath.Dir(absolute))
	if err != nil {
		return result, err
	}
	defer gate.Close()
	file, err := lockReleaseDirectory(absolute, syscall.LOCK_SH|syscall.LOCK_NB)
	if err != nil {
		return result, err
	}
	return VerifiedGitHubRelease{Tag: tag, Directory: absolute, lease: &releaseBundleLease{file: file}}, nil
}

// Directory inodes are locks; no lockfiles can leak or alter signed inventories.
// The cache inode gates open+flock, publication, and unlink so an opener cannot
// lease a deleted/replaced inode. Lease holders and Close never retain the gate.
// Bundle locks are nonblocking under the gate to avoid lock-order deadlocks.
func lockReleaseCacheGate(cache string) (*os.File, error) {
	if err := operatorPrivate(cache, true); err != nil {
		return nil, err
	}
	return lockReleaseDirectory(cache, syscall.LOCK_EX)
}
func lockReleaseDirectory(path string, operation int) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	fail := func(err error) (*os.File, error) { _ = file.Close(); return nil, err }
	info, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
		return fail(errors.New("unsafe release cache lock directory"))
	}
	if err := syscall.Flock(fd, operation); err != nil {
		return fail(err)
	}
	current, err := os.Lstat(path)
	if err != nil {
		return fail(err)
	}
	if !os.SameFile(info, current) {
		return fail(errors.New("release cache directory changed during locking"))
	}
	return file, nil
}

// Gate rename and lease acquisition, including collision verification.
func publishLeasedRelease(candidate, published, tag string) (VerifiedGitHubRelease, bool, error) {
	var result VerifiedGitHubRelease
	gate, err := lockReleaseCacheGate(filepath.Dir(published))
	if err != nil {
		return result, false, err
	}
	defer gate.Close()
	renamed := false
	if _, statErr := os.Lstat(published); os.IsNotExist(statErr) {
		if err := os.Rename(candidate, published); err != nil {
			return result, false, err
		}
		renamed = true
	} else if statErr != nil {
		return result, false, statErr
	}
	absolute, err := filepath.Abs(published)
	if err != nil {
		return result, renamed, err
	}
	file, err := lockReleaseDirectory(absolute, syscall.LOCK_SH|syscall.LOCK_NB)
	if err != nil {
		return result, renamed, err
	}
	return VerifiedGitHubRelease{Tag: tag, Directory: absolute, lease: &releaseBundleLease{file: file}}, renamed, nil
}

type githubReleaseInventory struct {
	Tag        string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

// FetchVerifiedGitHubRelease resolves a selector and atomically publishes a
// private read-only bundle only after verifying signatures and every asset.
func FetchVerifiedGitHubRelease(ctx context.Context, options GitHubReleaseOptions) (VerifiedGitHubRelease, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	var result VerifiedGitHubRelease
	if strings.TrimSpace(options.PublicKey) == "" {
		return result, errors.New("trusted minisign public key required")
	}
	signer := options.MinisignPath
	if signer == "" {
		var err error
		signer, err = resolveMinisignExecutable()
		if err != nil {
			return result, errors.New("minisign executable required")
		}
	}
	if _, err := exec.LookPath(signer); err != nil {
		return result, errors.New("minisign executable required")
	}
	selector := options.Selector
	latest := selector == "" || selector == "latest"
	endpoint := "https://api.github.com/repos/" + githubReleaseRepository + "/releases/latest"
	if !latest {
		if !stableReleaseTag.MatchString(selector) {
			return result, errors.New("invalid GitHub release selector")
		}
		endpoint = "https://api.github.com/repos/" + githubReleaseRepository + "/releases/tags/" + url.PathEscape(selector)
	}
	client := githubBoundedClient(options.Client)
	raw, err := githubDownload(ctx, client, endpoint, githubMetadataLimit)
	if err != nil {
		return result, err
	}
	var inventory githubReleaseInventory
	if json.Unmarshal(raw, &inventory) != nil || !stableReleaseTag.MatchString(inventory.Tag) || inventory.Draft || inventory.Prerelease || (!latest && inventory.Tag != selector) {
		return result, errors.New("invalid GitHub release identity or stability")
	}
	assets := map[string]string{}
	sizes := map[string]int64{}
	var total int64
	for _, asset := range inventory.Assets {
		if !githubAssetName.MatchString(asset.Name) || assets[asset.Name] != "" || asset.Size <= 0 || asset.Size > githubAssetLimit {
			return result, errors.New("invalid GitHub release inventory")
		}
		parsed, err := url.Parse(asset.URL)
		expected := "/" + githubReleaseRepository + "/releases/download/" + inventory.Tag + "/" + asset.Name
		if err != nil || !githubSafeURL(parsed) || parsed.Hostname() != "github.com" || parsed.Path != expected || parsed.RawQuery != "" {
			return result, errors.New("unsafe GitHub release asset URL")
		}
		total += asset.Size
		if total > githubBundleLimit {
			return result, errors.New("GitHub release exceeds bundle size limit")
		}
		assets[asset.Name], sizes[asset.Name] = asset.URL, asset.Size
	}
	if options.StagingBase == "" {
		return result, errors.New("release staging base required")
	}
	if err = os.MkdirAll(options.StagingBase, 0700); err != nil {
		return result, err
	}
	info, err := os.Lstat(options.StagingBase)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return result, errors.New("release staging base must be a private real directory")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return result, errors.New("release staging base must belong to the current user")
	}
	published := filepath.Join(options.StagingBase, "release-"+inventory.Tag)
	cached, statErr := AcquireVerifiedGitHubRelease(published, inventory.Tag)
	if statErr == nil {
		success := false
		defer func() {
			if !success {
				_ = cached.Close()
			}
		}()
		cachedManifest, verifyErr := verifySignedAutomationRelease(published, options.PublicKey, signer)
		if verifyErr != nil || cachedManifest.Version != inventory.Tag {
			return result, errors.New("cached release bundle failed revalidation; remove the local cache entry before retrying")
		}
		metadataDir, err := os.MkdirTemp(options.StagingBase, ".release-metadata-")
		if err != nil {
			return result, err
		}
		defer func() { _ = os.RemoveAll(metadataDir) }()
		for _, name := range []string{"release-manifest.json", "release-manifest.json.minisig", "checksums.txt", "checksums.txt.minisig"} {
			content, downloadErr := githubDownload(ctx, client, assets[name], githubMetadataLimit)
			if downloadErr != nil || int64(len(content)) != sizes[name] {
				return result, errors.New("could not revalidate cached release against GitHub metadata")
			}
			if err := os.WriteFile(filepath.Join(metadataDir, name), content, 0600); err != nil {
				return result, err
			}
		}
		currentManifest, verifyErr := signedReleaseMetadata(ctx, metadataDir, options.PublicKey, signer)
		if verifyErr != nil || currentManifest.Version != inventory.Tag || len(assets) != len(currentManifest.Assets)+3 {
			return result, errors.New("GitHub release metadata differs from the cached signed release")
		}
		cachedManifestBytes, cachedErr := os.ReadFile(filepath.Join(published, "release-manifest.json"))
		currentManifestBytes, currentErr := os.ReadFile(filepath.Join(metadataDir, "release-manifest.json"))
		if cachedErr != nil || currentErr != nil || !bytes.Equal(cachedManifestBytes, currentManifestBytes) {
			return result, errors.New("GitHub tag now identifies different signed release contents; clear the local cache explicitly")
		}
		for _, asset := range currentManifest.Assets {
			if sizes[asset.Name] != asset.Size {
				return result, errors.New("GitHub release inventory differs from cached signed manifest")
			}
		}
		success = true
		return cached, nil
	} else if !os.IsNotExist(statErr) {
		return result, statErr
	}
	directory, err := os.MkdirTemp(options.StagingBase, ".release-pending-")
	if err != nil {
		return result, err
	}
	defer func() {
		if directory != "" {
			_ = os.Chmod(directory, 0700)
			_ = os.RemoveAll(directory)
		}
	}()
	download := func(name string, limit int64) error {
		address, ok := assets[name]
		if !ok {
			return fmt.Errorf("missing release asset %s", name)
		}
		content, err := githubDownload(ctx, client, address, limit)
		if err != nil {
			return err
		}
		if int64(len(content)) != sizes[name] {
			return fmt.Errorf("release asset size mismatch: %s", name)
		}
		return os.WriteFile(filepath.Join(directory, name), content, 0600)
	}
	for _, name := range []string{"release-manifest.json", "release-manifest.json.minisig", "checksums.txt", "checksums.txt.minisig"} {
		if err = download(name, githubMetadataLimit); err != nil {
			return result, err
		}
	}
	manifest, err := signedReleaseMetadata(ctx, directory, options.PublicKey, signer)
	if err != nil {
		return result, err
	}
	if manifest.Version != inventory.Tag {
		return result, errors.New("signed manifest release tag mismatch")
	}
	if len(assets) != len(manifest.Assets)+3 {
		return result, errors.New("unexpected GitHub release inventory")
	}
	for _, asset := range manifest.Assets {
		if sizes[asset.Name] != asset.Size {
			return result, errors.New("GitHub inventory differs from signed manifest")
		}
		if asset.Name != "checksums.txt" {
			if err = download(asset.Name, asset.Size); err != nil {
				return result, err
			}
		}
	}
	if _, err = verifyAutomationRelease(directory, inventory.Tag); err != nil {
		return result, err
	}
	for name := range assets {
		if err = os.Chmod(filepath.Join(directory, name), 0400); err != nil {
			return result, err
		}
	}
	if err = os.Chmod(directory, 0500); err != nil {
		return result, err
	}
	leased, renamed, err := publishLeasedRelease(directory, published, inventory.Tag)
	if err != nil {
		return result, err
	}
	success := false
	defer func() {
		if !success {
			_ = leased.Close()
		}
	}()
	if !renamed {
		if manifest, verifyErr := verifySignedAutomationRelease(published, options.PublicKey, signer); verifyErr != nil || manifest.Version != inventory.Tag {
			return result, errors.New("signed release cache conflicts with downloaded bundle")
		}
		cachedManifestBytes, cachedErr := os.ReadFile(filepath.Join(published, "release-manifest.json"))
		candidateManifestBytes, candidateErr := os.ReadFile(filepath.Join(directory, "release-manifest.json"))
		if cachedErr != nil || candidateErr != nil || !bytes.Equal(cachedManifestBytes, candidateManifestBytes) {
			return result, errors.New("GitHub release tag already has different signed contents in the local cache")
		}
	} else {
		directory = ""
	}
	success = true
	return leased, nil
}

// VerifySignedAutomationRelease revalidates retained local bundles. Unsigned
// local directories are never trusted, and every invocation rechecks all hashes.
func VerifySignedAutomationRelease(directory, publicKey string) (*automationRelease, error) {
	signer, err := resolveMinisignExecutable()
	if err != nil {
		return nil, errors.New("minisign executable required")
	}
	return verifySignedAutomationRelease(directory, publicKey, signer)
}

// SnapshotSignedAutomationRelease copies a caller-selected bundle into a
// private immutable cache before trusting or handing it to another process.
// Verification is performed on the copied bytes, closing the verify/use race
// for mutable --release-dir inputs.
func SnapshotSignedAutomationRelease(source, publicKey, stagingBase string) (VerifiedGitHubRelease, error) {
	signer, err := resolveMinisignExecutable()
	if err != nil {
		return VerifiedGitHubRelease{}, errors.New("minisign executable required")
	}
	return snapshotSignedAutomationRelease(source, publicKey, stagingBase, signer)
}

func snapshotSignedAutomationRelease(source, publicKey, stagingBase, signer string) (VerifiedGitHubRelease, error) {
	var result VerifiedGitHubRelease
	if strings.TrimSpace(publicKey) == "" {
		return result, errors.New("trusted minisign public key required")
	}
	if err := preparePrivateReleaseStage(stagingBase); err != nil {
		return result, err
	}
	sourceInfo, err := os.Lstat(source)
	if err != nil || !sourceInfo.IsDir() || sourceInfo.Mode()&os.ModeSymlink != 0 {
		return result, errors.New("local release directory unavailable or unsafe")
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		return result, errors.New("local release directory unavailable")
	}
	directory, err := os.MkdirTemp(stagingBase, ".release-snapshot-")
	if err != nil {
		return result, err
	}
	defer func() {
		if directory != "" {
			_ = os.Chmod(directory, 0700)
			_ = os.RemoveAll(directory)
		}
	}()
	var total int64
	for _, entry := range entries {
		name := entry.Name()
		if !githubAssetName.MatchString(name) {
			return result, errors.New("unsafe local release asset name")
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > githubAssetLimit {
			return result, errors.New("local release asset unavailable or unsafe")
		}
		total += info.Size()
		if total > githubBundleLimit+4*githubMetadataLimit {
			return result, errors.New("local release exceeds bundle size limit")
		}
		fd, err := syscall.Open(filepath.Join(source, name), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
		if err != nil {
			return result, errors.New("local release asset changed or is unsafe")
		}
		input := os.NewFile(uintptr(fd), name)
		opened, statErr := input.Stat()
		if statErr != nil || !opened.Mode().IsRegular() || opened.Size() != info.Size() {
			_ = input.Close()
			return result, errors.New("local release asset changed during snapshot")
		}
		output, createErr := os.OpenFile(filepath.Join(directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if createErr != nil {
			_ = input.Close()
			return result, createErr
		}
		written, copyErr := io.Copy(output, io.LimitReader(input, info.Size()+1))
		closeOutErr := output.Close()
		closeInErr := input.Close()
		if copyErr != nil || closeOutErr != nil || closeInErr != nil || written != info.Size() {
			return result, errors.New("failed to copy complete local release asset")
		}
	}
	manifest, err := verifySignedAutomationRelease(directory, publicKey, signer)
	if err != nil {
		return result, err
	}
	for _, entry := range entries {
		if err := os.Chmod(filepath.Join(directory, entry.Name()), 0400); err != nil {
			return result, err
		}
	}
	if err := os.Chmod(directory, 0500); err != nil {
		return result, err
	}
	published := filepath.Join(stagingBase, "release-"+manifest.Version)
	leased, renamed, err := publishLeasedRelease(directory, published, manifest.Version)
	if err != nil {
		return result, err
	}
	success := false
	defer func() {
		if !success {
			_ = leased.Close()
		}
	}()
	if !renamed {
		existing, verifyErr := verifySignedAutomationRelease(published, publicKey, signer)
		if verifyErr != nil || existing.Version != manifest.Version {
			return result, errors.New("signed release cache conflicts with the selected bundle")
		}
		original, originalErr := os.ReadFile(filepath.Join(published, "release-manifest.json"))
		copied, copiedErr := os.ReadFile(filepath.Join(directory, "release-manifest.json"))
		if originalErr != nil || copiedErr != nil || !bytes.Equal(original, copied) {
			return result, errors.New("signed release cache already contains a different bundle for this tag")
		}
	} else {
		directory = ""
	}
	success = true
	return leased, nil
}

func resolveMinisignExecutable() (string, error) {
	if override := strings.TrimSpace(os.Getenv(upgradeMinisignPathEnv)); override != "" {
		if !filepath.IsAbs(override) {
			return "", errors.New("minisign override must be absolute")
		}
		info, err := os.Stat(override)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			return "", errors.New("minisign override is unavailable")
		}
		return filepath.Clean(override), nil
	}
	path, err := exec.LookPath("minisign")
	if err != nil {
		return "", err
	}
	return filepath.Abs(path)
}

func preparePrivateReleaseStage(path string) error {
	if path == "" {
		return errors.New("release staging base required")
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("release staging base must be a private real directory")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return errors.New("release staging base must belong to the current user")
	}
	return nil
}

func verifySignedAutomationRelease(directory, publicKey, signer string) (*automationRelease, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() {
		return nil, errors.New("local release directory unavailable or unsafe")
	}
	manifest, err := signedReleaseMetadata(ctx, directory, publicKey, signer)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	if len(entries) != len(manifest.Assets)+3 {
		return nil, errors.New("unexpected local release inventory")
	}
	expected := map[string]bool{"release-manifest.json": true, "release-manifest.json.minisig": true, "checksums.txt.minisig": true}
	for _, asset := range manifest.Assets {
		expected[asset.Name] = true
	}
	for _, entry := range entries {
		if !expected[entry.Name()] {
			return nil, errors.New("unexpected local release asset")
		}
	}
	return verifyAutomationRelease(directory, manifest.Version)
}

func signedReleaseMetadata(ctx context.Context, directory, key, signer string) (*automationRelease, error) {
	if strings.TrimSpace(key) == "" {
		return nil, errors.New("trusted minisign public key required")
	}
	for _, name := range []string{"release-manifest.json", "checksums.txt"} {
		for _, file := range []string{name, name + ".minisig"} {
			info, err := os.Lstat(filepath.Join(directory, file))
			if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > githubMetadataLimit {
				return nil, errors.New("signed release metadata unavailable or unsafe")
			}
		}
		verifyContext, cancel := context.WithTimeout(ctx, 30*time.Second)
		command := exec.CommandContext(verifyContext, signer, "-Vm", filepath.Join(directory, name), "-x", filepath.Join(directory, name+".minisig"), "-P", key)
		err := command.Run()
		cancel()
		if err != nil {
			return nil, fmt.Errorf("minisign verification failed for %s", name)
		}
	}
	raw, err := os.ReadFile(filepath.Join(directory, "release-manifest.json"))
	if err != nil {
		return nil, err
	}
	var manifest automationRelease
	if json.Unmarshal(raw, &manifest) != nil || manifest.SchemaVersion != 1 || !stableReleaseTag.MatchString(manifest.Version) || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(manifest.SourceCommit) || manifest.DatabaseSchemaMin <= 0 || manifest.DatabaseSchemaMax < manifest.DatabaseSchemaMin {
		return nil, errors.New("invalid signed release manifest")
	}
	if !hasAutomationCapability(&manifest, "ansible-deploy-v1") {
		return nil, errors.New("signed release lacks ansible-deploy-v1 capability")
	}
	// Keep this contract aligned with scripts/build-release-manifest.sh.
	required := map[string]bool{
		"ultra-install-linux-amd64": true, "ultra-install-linux-arm64": true,
		"ultra-relay-linux-amd64": true, "ultra-relay-linux-arm64": true,
		"ultra-bot-linux-amd64": true, "ultra-bot-linux-arm64": true,
		"ultra-client-linux-amd64": true, "ultra-client-linux-arm64": true,
		"ultra-recovery.tar.gz": true, "ultra-ansible.tar.gz": true,
		"ultra-ansible-runtime-linux-amd64.tar.gz": true,
		"ultra-ansible-runtime-linux-arm64.tar.gz": true,
		"mobile-bootstrap.sh":                      true, "checksums.txt": true,
	}
	if len(manifest.Assets) != len(required) {
		return nil, errors.New("signed manifest differs from published asset inventory")
	}
	rows := map[string]string{}
	var total int64
	for _, asset := range manifest.Assets {
		if !required[asset.Name] || !githubAssetName.MatchString(asset.Name) || asset.Name == "release-manifest.json" || strings.HasSuffix(asset.Name, ".minisig") || rows[asset.Name] != "" || !githubSHA.MatchString(asset.SHA) || asset.Size <= 0 || asset.Size > githubAssetLimit {
			return nil, errors.New("invalid signed manifest asset")
		}
		total += asset.Size
		if total > githubBundleLimit {
			return nil, errors.New("signed manifest exceeds bundle size limit")
		}
		rows[asset.Name] = asset.SHA
	}
	if rows["checksums.txt"] == "" {
		return nil, errors.New("signed manifest lacks checksums")
	}
	checksums, err := os.ReadFile(filepath.Join(directory, "checksums.txt"))
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(checksums)
	if hex.EncodeToString(digest[:]) != rows["checksums.txt"] {
		return nil, errors.New("signed checksums differ from manifest")
	}
	seen := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(string(checksums)))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 67 || line[64:66] != "  " || !githubSHA.MatchString(line[:64]) {
			return nil, errors.New("invalid signed checksum row")
		}
		name := line[66:]
		if name == "checksums.txt" || seen[name] || rows[name] != line[:64] {
			return nil, errors.New("signed checksum inventory mismatch")
		}
		seen[name] = true
	}
	if scanner.Err() != nil || len(seen) != len(rows)-1 {
		return nil, errors.New("incomplete signed checksum inventory")
	}
	return &manifest, nil
}

func githubSafeURL(address *url.URL) bool {
	if address == nil || address.Scheme != "https" || address.User != nil || address.Fragment != "" || address.Opaque != "" || (address.Port() != "" && address.Port() != "443") {
		return false
	}
	switch address.Hostname() {
	case "github.com", "api.github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com":
		return true
	}
	return false
}
func githubBoundedClient(original *http.Client) *http.Client {
	client := &http.Client{}
	if original != nil {
		*client = *original
	}
	if client.Timeout <= 0 || client.Timeout > 2*time.Minute {
		client.Timeout = 2 * time.Minute
	}
	previous := client.CheckRedirect
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 || !githubSafeURL(request.URL) {
			return errors.New("unsafe GitHub download redirect")
		}
		if previous != nil {
			return previous(request, via)
		}
		return nil
	}
	return client
}
func githubDownload(ctx context.Context, client *http.Client, address string, limit int64) ([]byte, error) {
	parsed, err := url.Parse(address)
	if err != nil || !githubSafeURL(parsed) {
		return nil, errors.New("unsafe GitHub download URL")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "ultra-install")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub download HTTP status %d", response.StatusCode)
	}
	if response.ContentLength > limit {
		return nil, errors.New("GitHub download exceeds size limit")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("GitHub download exceeds size limit")
	}
	return raw, nil
}
