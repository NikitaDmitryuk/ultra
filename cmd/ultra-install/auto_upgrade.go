package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

type autoUpgradePolicy struct {
	Enabled                bool     `json:"enabled"`
	Repository             string   `json:"repository"`
	PublicKeyFile          string   `json:"public_key_file"`
	ConfigFile             string   `json:"config_file"`
	StateDirectory         string   `json:"state_directory"`
	OperationLockDirectory string   `json:"operation_lock_directory"`
	ChannelStateFile       string   `json:"channel_state_file"`
	CurrentManifest        string   `json:"current_manifest"`
	Python                 string   `json:"python"`
	Ansible                string   `json:"ansible"`
	RequiredChecks         []string `json:"required_checks"`
}

type githubStableRelease struct {
	Tag        string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func runAutoUpgradeCommand(args []string) {
	fs := flag.NewFlagSet("auto-upgrade", flag.ExitOnError)
	policy := fs.String("policy", "/etc/ultra-ansible/auto-upgrade.json", "private generated auto-update policy")
	_ = fs.Parse(args)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	exitOnErr("automatic upgrade", autoUpgrade(ctx, *policy))
}

func autoUpgrade(ctx context.Context, policyPath string) error {
	info, err := os.Lstat(policyPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 65536 {
		return errors.New("auto_policy_invalid")
	}
	raw, err := os.ReadFile(policyPath)
	if err != nil {
		return errors.New("auto_policy_unavailable")
	}
	var policy autoUpgradePolicy
	if json.Unmarshal(raw, &policy) != nil {
		return errors.New("auto_policy_invalid")
	}
	if !policy.Enabled {
		return nil
	}
	if policy.OperationLockDirectory == "" {
		policy.OperationLockDirectory = "/var/lib/ultra-ansible"
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`).MatchString(policy.Repository) || len(policy.RequiredChecks) == 0 {
		return errors.New("auto_repository_or_checks_invalid")
	}
	for _, path := range []string{channelPath(policy), policy.PublicKeyFile, policy.ConfigFile, policy.StateDirectory, policy.OperationLockDirectory, policy.CurrentManifest, policy.Python} {
		if !filepath.IsAbs(path) {
			return errors.New("auto_policy_paths_invalid")
		}
	}
	if err = ensurePrivateBootstrapDirectory(policy.StateDirectory); err != nil {
		return err
	}
	if err = ensurePrivateBootstrapDirectory(policy.OperationLockDirectory); err != nil {
		return err
	}
	// This lock only serializes pollers; ansibleUpgrade owns the infrastructure lease.
	pollerDirectory := filepath.Join(policy.StateDirectory, "poller-lock")
	if err = os.MkdirAll(pollerDirectory, 0700); err != nil {
		return err
	}
	_, release, err := deployansible.WithOperationLock(ctx, pollerDirectory)
	if err != nil {
		return err
	}
	defer release()
	client := &http.Client{Timeout: 60 * time.Second}
	if err = reconstructPublishedChannel(ctx, policy); err != nil {
		return err
	}
	if resumed, err := resumePendingAutoUpgrade(ctx, client, policy); resumed || err != nil {
		return err
	}
	releaseInfo := githubStableRelease{}
	if err = githubJSON(ctx, client, "https://api.github.com/repos/"+policy.Repository+"/releases/latest", &releaseInfo); err != nil {
		return errors.New("auto_release_preflight_unavailable")
	}
	if releaseInfo.Draft || releaseInfo.Prerelease || !stableVersion(releaseInfo.Tag) {
		return errors.New("auto_release_not_stable")
	}
	currentRaw, err := os.ReadFile(policy.CurrentManifest)
	if err != nil {
		return errors.New("auto_current_manifest_unavailable")
	}
	var current automationRelease
	if json.Unmarshal(currentRaw, &current) != nil || !stableVersion(current.Version) {
		return errors.New("auto_current_manifest_invalid")
	}
	channel, err := readChannelState(channelPath(policy))
	if err != nil {
		return err
	}
	if channel.Failed[releaseInfo.Tag] != "" {
		return errors.New("auto_failed_version_blocked")
	}
	if !versionGreater(releaseInfo.Tag, current.Version) {
		return nil
	}
	if _, err = os.Stat(filepath.Join(policy.StateDirectory, "failed-"+releaseInfo.Tag+".json")); err == nil {
		return errors.New("auto_failed_version_blocked")
	}
	target, err := prepareAutoReleaseWithRetention(ctx, client, policy, releaseInfo)
	if err != nil {
		return err
	}
	err = handoffAutoUpgrade(ctx, policy, target, releaseInfo.Tag)
	if err != nil {
		if _, activationErr := os.Stat(filepath.Join(policy.OperationLockDirectory, "operation-"+releaseInfo.Tag, "activate", "job.json")); activationErr == nil {
			if identity, identityErr := targetChannelIdentity(target, releaseInfo.Tag); identityErr == nil {
				if stateErr := updateChannelState(policy, identity, "activation_failed"); stateErr != nil {
					return stateErr
				}
			}
		}
		return errors.New("auto_release_activation_failed")
	}
	return nil
}

func stableVersion(version string) bool {
	return regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(version)
}
func versionGreater(next, current string) bool {
	if !stableVersion(next) || !stableVersion(current) {
		return false
	}
	a, b := strings.Split(next[1:], "."), strings.Split(current[1:], ".")
	for i := range a {
		left, errA := strconv.ParseUint(a[i], 10, 64)
		right, errB := strconv.ParseUint(b[i], 10, 64)
		if errA != nil || errB != nil {
			return false
		}
		if left != right {
			return left > right
		}
	}
	return false
}
func githubJSON(ctx context.Context, client *http.Client, address string, result any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close() //nolint:errcheck
	if response.StatusCode != http.StatusOK {
		return errors.New("github_request_failed")
	}
	return json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(result)
}
func verifyGithubCI(ctx context.Context, client *http.Client, repository, tag, commit string, required []string) error {
	var reference struct {
		Object struct {
			Type string `json:"type"`
			SHA  string `json:"sha"`
		} `json:"object"`
	}
	if githubJSON(ctx, client, "https://api.github.com/repos/"+repository+"/git/ref/tags/"+url.PathEscape(tag), &reference) != nil {
		return errors.New("auto_tag_unavailable")
	}
	for i := 0; reference.Object.Type == "tag" && i < 4; i++ {
		var annotated struct {
			Object struct {
				Type string `json:"type"`
				SHA  string `json:"sha"`
			} `json:"object"`
		}
		if githubJSON(ctx, client, "https://api.github.com/repos/"+repository+"/git/tags/"+reference.Object.SHA, &annotated) != nil {
			return errors.New("auto_tag_invalid")
		}
		reference.Object.Type = annotated.Object.Type
		reference.Object.SHA = annotated.Object.SHA
	}
	if reference.Object.Type != "commit" || reference.Object.SHA != commit {
		return errors.New("auto_tag_commit_mismatch")
	}
	var checks struct {
		Total int `json:"total_count"`
		Runs  []struct {
			Name       string `json:"name"`
			HeadSHA    string `json:"head_sha"`
			Status     string `json:"status"`
			Conclusion string `json:"conclusion"`
			App        struct {
				Slug string `json:"slug"`
			} `json:"app"`
		} `json:"check_runs"`
	}
	if githubJSON(ctx, client, "https://api.github.com/repos/"+repository+"/commits/"+commit+"/check-runs?filter=latest&per_page=100", &checks) != nil || checks.Total > 100 {
		return errors.New("auto_ci_unavailable")
	}
	for _, name := range required {
		found := false
		for _, check := range checks.Runs {
			if check.Name == name && check.HeadSHA == commit && check.App.Slug == "github-actions" {
				if check.Status != "completed" || check.Conclusion != "success" {
					return errors.New("auto_ci_not_successful")
				}
				found = true
			}
		}
		if !found {
			return fmt.Errorf("auto_required_ci_missing")
		}
	}
	return nil
}
func downloadAutoAsset(ctx context.Context, client *http.Client, address, destination string, limit int64) error {
	parsed, err := url.Parse(address)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "github.com" || parsed.User != nil {
		return errors.New("auto_asset_origin_invalid")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close() //nolint:errcheck
	if response.StatusCode != http.StatusOK {
		return errors.New("auto_asset_unavailable")
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close() //nolint:errcheck
	size, err := io.Copy(file, io.LimitReader(response.Body, limit+1))
	if err != nil || size > limit {
		return errors.New("auto_asset_size_invalid")
	}
	return file.Sync()
}

// The signed target installer contains the target's embedded operation bundle.
// An old polling binary must never run its own roles to install a newer version.
func handoffAutoUpgrade(ctx context.Context, policy autoUpgradePolicy, directory, version string) error {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return errors.New("auto_controller_architecture_unsupported")
	}
	manifest, err := verifyAutomationRelease(directory, version)
	if err != nil {
		return err
	}
	if !hasAutomationCapability(manifest, "ansible-deploy-v1") {
		return errors.New("auto_target_ansible_contract_missing")
	}
	installer, err := upgradeAsset(manifest, "ultra-install-linux-"+runtime.GOARCH)
	if err != nil {
		return err
	}
	if _, err = upgradeAsset(manifest, "ultra-ansible-runtime-linux-"+runtime.GOARCH+".tar.gz"); err != nil {
		return err
	}
	executable := filepath.Join(directory, installer.Name)
	if err = os.Chmod(executable, 0700); err != nil {
		return err
	}
	identity, err := targetChannelIdentity(directory, version)
	if err != nil {
		return err
	}
	if err = updateChannelState(policy, identity, "pending"); err != nil {
		return err
	}
	operationDirectory := filepath.Join(policy.OperationLockDirectory, "operation-"+version)
	if err = ensurePrivateBootstrapDirectory(operationDirectory); err != nil {
		return err
	}
	configSnapshot := filepath.Join(operationDirectory, "install.config")
	if _, statErr := os.Lstat(configSnapshot); os.IsNotExist(statErr) {
		raw, readErr := os.ReadFile(policy.ConfigFile)
		if readErr != nil {
			return errors.New("auto_config_unavailable")
		}
		if err = writeUpgradeInput(configSnapshot, raw); err != nil {
			return err
		}
	} else if statErr != nil {
		return statErr
	}
	command := exec.CommandContext(ctx, executable, "upgrade", "--config", configSnapshot, "--release-dir", directory, "--job-dir", filepath.Join(policy.OperationLockDirectory, "operation-"+version), "--python", policy.Python)
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	// The target resolves its own verified runtime; current/old Ansible is not an override.
	if command.Run() != nil {
		return errors.New("auto_target_installer_failed")
	}
	commitDirectory, err := autoUpgradeCommitDirectory(filepath.Join(policy.OperationLockDirectory, "operation-"+version))
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(commitDirectory, "receipt.json"))
	var receipt deployansible.Receipt
	if err != nil || json.Unmarshal(raw, &receipt) != nil || receipt.State != "succeeded" || receipt.Result.Values["verified"] != true || receipt.Result.Values["version"] != version {
		return errors.New("auto_target_commit_receipt_unavailable")
	}
	return updateChannelState(policy, identity, "accepted")
}

// A published candidate is not a committed release. Resume an interrupted signed
// frozen operation before latest/version equality can accidentally suppress it.
func resumePendingAutoUpgrade(ctx context.Context, client *http.Client, policy autoUpgradePolicy) (bool, error) {
	versions, err := pendingAutoUpgradeVersions(policy)
	if err != nil {
		return false, err
	}
	if len(versions) == 0 {
		return false, nil
	}
	version := versions[0]
	{
		target := filepath.Join(policy.StateDirectory, version)
		if _, statErr := os.Stat(target); os.IsNotExist(statErr) {
			var exact githubStableRelease
			if fetchErr := githubJSON(ctx, client, "https://api.github.com/repos/"+policy.Repository+"/releases/tags/"+version, &exact); fetchErr != nil || exact.Tag != version || exact.Draft || exact.Prerelease {
				return true, errors.New("auto_pending_exact_release_unavailable")
			}
			var prepareErr error
			target, prepareErr = prepareAutoReleaseWithRetention(ctx, client, policy, exact)
			if prepareErr != nil {
				return true, prepareErr
			}
		}
		manifest, err := verifyAutomationRelease(target, version)
		if err != nil {
			return true, errors.New("auto_pending_release_invalid")
		}
		channel, stateErr := readChannelState(channelPath(policy))
		if stateErr != nil {
			return true, stateErr
		}
		identity, identityErr := targetChannelIdentity(target, version)
		if identityErr != nil {
			return true, identityErr
		}
		if channel.Pending != nil && *channel.Pending != *identity {
			return true, errors.New("auto_pending_identity_changed")
		}
		signature := exec.CommandContext(ctx, "/usr/bin/minisign", "-V", "-p", policy.PublicKeyFile, "-m", filepath.Join(target, "release-manifest.json"), "-x", filepath.Join(target, "release-manifest.json.minisig"))
		if signature.Run() != nil {
			return true, errors.New("auto_pending_signature_invalid")
		}
		if err = verifyGithubCI(ctx, client, policy.Repository, version, manifest.SourceCommit, policy.RequiredChecks); err != nil {
			return true, err
		}
		if err = handoffAutoUpgrade(ctx, policy, target, version); err != nil {
			if _, activationErr := os.Stat(filepath.Join(policy.OperationLockDirectory, "operation-"+version, "activate", "job.json")); activationErr == nil {
				if identity, identityErr := targetChannelIdentity(target, version); identityErr == nil {
					if stateErr := updateChannelState(policy, identity, "resume_failed"); stateErr != nil {
						return true, stateErr
					}
				}
			}
			return true, errors.New("auto_pending_release_failed")
		}
		return true, nil
	}
}

func pendingAutoUpgradeVersions(policy autoUpgradePolicy) ([]string, error) {
	channel, err := readChannelState(channelPath(policy))
	if err != nil {
		return nil, err
	}
	if channel.Pending != nil && channel.Failed[channel.Pending.Version] == "" {
		return []string{channel.Pending.Version}, nil
	}
	entries, err := os.ReadDir(policy.OperationLockDirectory)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var versions []string
	for _, entry := range entries {
		version := strings.TrimPrefix(entry.Name(), "operation-")
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasPrefix(entry.Name(), "operation-") || !stableVersion(version) {
			continue
		}
		if channel.Failed[version] != "" {
			continue
		}
		job := filepath.Join(policy.OperationLockDirectory, entry.Name())
		if _, err = os.Stat(filepath.Join(job, "install.config")); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return nil, err
		}
		var receipt deployansible.Receipt
		commitDirectory, generationErr := autoUpgradeCommitDirectory(job)
		if generationErr != nil {
			return nil, generationErr
		}
		if raw, readErr := os.ReadFile(filepath.Join(commitDirectory, "receipt.json")); readErr == nil && json.Unmarshal(raw, &receipt) == nil && receipt.State == "succeeded" && receipt.Result.Values["version"] == version && receipt.Result.Values["verified"] == true {
			continue
		}
		if _, err = os.Stat(filepath.Join(policy.StateDirectory, "failed-"+version+".json")); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		versions = append(versions, version)
	}
	return versions, nil
}

func prepareAutoRelease(ctx context.Context, client *http.Client, policy autoUpgradePolicy, releaseInfo githubStableRelease) (string, error) {
	if err := autoDownloadCapacity(policy.StateDirectory, releaseInfo.Tag); err != nil {
		return "", err
	}
	urls := map[string]string{}
	for _, asset := range releaseInfo.Assets {
		if _, ok := urls[asset.Name]; ok {
			return "", errors.New("auto_duplicate_asset")
		}
		urls[asset.Name] = asset.URL
	}
	incoming, err := os.MkdirTemp(policy.StateDirectory, "download-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(incoming) //nolint:errcheck
	for _, name := range []string{"release-manifest.json", "release-manifest.json.minisig"} {
		if err = downloadAutoAsset(ctx, client, urls[name], filepath.Join(incoming, name), 1<<20); err != nil {
			return "", errors.New("auto_signed_manifest_unavailable")
		}
	}
	command := exec.CommandContext(ctx, "/usr/bin/minisign", "-V", "-p", policy.PublicKeyFile, "-m", filepath.Join(incoming, "release-manifest.json"), "-x", filepath.Join(incoming, "release-manifest.json.minisig"))
	if command.Run() != nil {
		return "", errors.New("auto_manifest_signature_invalid")
	}
	raw, err := os.ReadFile(filepath.Join(incoming, "release-manifest.json"))
	if err != nil {
		return "", err
	}
	var manifest automationRelease
	if json.Unmarshal(raw, &manifest) != nil || manifest.Version != releaseInfo.Tag || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(manifest.SourceCommit) {
		return "", errors.New("auto_manifest_commit_invalid")
	}
	if err = verifyGithubCI(ctx, client, policy.Repository, releaseInfo.Tag, manifest.SourceCommit, policy.RequiredChecks); err != nil {
		return "", err
	}
	required, err := autoDownloadRequiredBytes(manifest)
	if err != nil {
		return "", err
	}
	available, err := autoDownloadAvailableBytes(policy.StateDirectory)
	if err != nil {
		return "", err
	}
	if err = autoDownloadDiskAdmission(required, available); err != nil {
		return "", err
	}
	for _, asset := range manifest.Assets {
		if filepath.Base(asset.Name) != asset.Name || asset.Name == "." || asset.Size <= 0 || asset.Size > 256<<20 {
			return "", errors.New("auto_asset_metadata_invalid")
		}
		if err = downloadAutoAsset(ctx, client, urls[asset.Name], filepath.Join(incoming, asset.Name), asset.Size); err != nil {
			return "", errors.New("auto_asset_download_incomplete")
		}
	}
	if _, err = verifyAutomationRelease(incoming, releaseInfo.Tag); err != nil {
		return "", err
	}
	target := filepath.Join(policy.StateDirectory, releaseInfo.Tag)
	if _, err = os.Lstat(target); err == nil {
		existing, err := os.ReadFile(filepath.Join(target, "release-manifest.json"))
		if err != nil || string(existing) != string(raw) {
			return "", errors.New("auto_release_directory_conflict")
		}
		if _, err = verifyAutomationRelease(target, releaseInfo.Tag); err != nil {
			return "", err
		}
	} else if os.IsNotExist(err) {
		if err = sealAutoDownload(policy, incoming, target, manifest); err != nil {
			return "", err
		}
		if err = os.Rename(incoming, target); err != nil {
			return "", err
		}
		parent, openErr := os.Open(policy.StateDirectory)
		if openErr != nil {
			return "", openErr
		}
		syncErr := parent.Sync()
		closeErr := parent.Close()
		if syncErr != nil {
			return "", syncErr
		}
		if closeErr != nil {
			return "", closeErr
		}
	} else {
		return "", err
	}
	return target, nil
}
