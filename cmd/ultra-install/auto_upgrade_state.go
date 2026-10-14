package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"
)

type channelIdentity struct {
	Version        string `json:"version"`
	SourceCommit   string `json:"source_commit"`
	ManifestSHA256 string `json:"manifest_sha256"`
}
type channelState struct {
	Schema   int               `json:"schema_version"`
	Accepted *channelIdentity  `json:"accepted,omitempty"`
	Pending  *channelIdentity  `json:"pending,omitempty"`
	Failed   map[string]string `json:"failed"`
}

func channelPath(policy autoUpgradePolicy) string {
	if policy.ChannelStateFile != "" {
		return policy.ChannelStateFile
	}
	return filepath.Join(policy.OperationLockDirectory, "channel", "state.json")
}
func validateChannelIdentity(value *channelIdentity) bool {
	return value == nil || (stableVersion(value.Version) && regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(value.SourceCommit) && regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(value.ManifestSHA256))
}
func readChannelState(path string) (channelState, error) {
	state := channelState{Schema: 1, Failed: map[string]string{}}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 65536 {
		return state, errors.New("auto_channel_state_invalid")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return state, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.Decode(new(any)) != io.EOF || state.Schema != 1 || !validateChannelIdentity(state.Accepted) || !validateChannelIdentity(state.Pending) || len(state.Failed) > 128 {
		return state, errors.New("auto_channel_state_invalid")
	}
	for version, code := range state.Failed {
		if !stableVersion(version) || (code != "activation_failed" && code != "resume_failed") {
			return state, errors.New("auto_channel_state_invalid")
		}
	}
	if state.Failed == nil {
		state.Failed = map[string]string{}
	}
	return state, nil
}

// Poller mutex or infrastructure lease must already be held by the caller.
func updateChannelState(policy autoUpgradePolicy, identity *channelIdentity, action string) error {
	path := channelPath(policy)
	if !filepath.IsAbs(path) {
		return errors.New("auto_channel_path_invalid")
	}
	if err := ensurePrivateBootstrapDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	lockDirectory := filepath.Join(filepath.Dir(path), "metadata-lock")
	if err := ensurePrivateBootstrapDirectory(lockDirectory); err != nil {
		return err
	}
	_, unlock, err := deployansible.WithOperationLock(ctx, lockDirectory)
	if err != nil {
		return err
	}
	defer unlock()
	state, err := readChannelState(path)
	if err != nil {
		return err
	}
	if !validateChannelIdentity(identity) || identity == nil {
		return errors.New("auto_channel_identity_invalid")
	}
	switch action {
	case "pending":
		if state.Pending != nil && *state.Pending != *identity && state.Failed[state.Pending.Version] == "" {
			return errors.New("auto_channel_pending_conflict")
		}
		state.Pending = identity
	case "accepted":
		if state.Failed[identity.Version] != "" {
			return errors.New("auto_failed_version_explicit_retry_required")
		}
		if state.Pending != nil && *state.Pending != *identity {
			return errors.New("auto_channel_pending_conflict")
		}
		state.Accepted = identity
		state.Pending = nil
	case "activation_failed", "resume_failed":
		state.Failed[identity.Version] = action
	default:
		return errors.New("auto_channel_action_invalid")
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return replaceUpgradeMetadata(path, raw)
}
func targetChannelIdentity(directory, version string) (*channelIdentity, error) {
	manifest, err := verifyAutomationRelease(directory, version)
	if err != nil {
		return nil, err
	}
	digest, err := sourceSHA(filepath.Join(directory, "release-manifest.json"))
	if err != nil {
		return nil, err
	}
	value := &channelIdentity{Version: version, SourceCommit: manifest.SourceCommit, ManifestSHA256: digest}
	if !validateChannelIdentity(value) {
		return nil, errors.New("auto_channel_identity_invalid")
	}
	return value, nil
}
func runVerifyChannelState(args []string) {
	fs := flag.NewFlagSet("verify-channel-state", flag.ExitOnError)
	path := fs.String("file", "/var/lib/ultra-ansible/channel/state.json", "private identity-only channel metadata")
	_ = fs.Parse(args)
	_, err := readChannelState(*path)
	exitOnErr("channel metadata validation", err)
}

// Restore carries identity-only metadata, never frozen host inventories. An exact
// signed published candidate lacking acceptance reconstructs a fresh operation.
func reconstructPublishedChannel(ctx context.Context, policy autoUpgradePolicy) error {
	state, err := readChannelState(channelPath(policy))
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(policy.CurrentManifest)
	if err != nil {
		return errors.New("auto_current_manifest_unavailable")
	}
	var manifest automationRelease
	if json.Unmarshal(raw, &manifest) != nil {
		return errors.New("auto_current_manifest_invalid")
	}
	digest, err := sourceSHA(policy.CurrentManifest)
	if err != nil {
		return err
	}
	identity := &channelIdentity{Version: manifest.Version, SourceCommit: manifest.SourceCommit, ManifestSHA256: digest}
	if !validateChannelIdentity(identity) {
		return errors.New("auto_current_manifest_identity_invalid")
	}
	if state.Accepted != nil && *state.Accepted == *identity {
		return nil
	}
	if state.Pending != nil {
		return nil
	}
	if state.Failed[identity.Version] != "" {
		return nil // A newer fixed release may proceed; this exact candidate remains blocked.
	}
	signature := exec.CommandContext(ctx, "/usr/bin/minisign", "-V", "-p", policy.PublicKeyFile, "-m", policy.CurrentManifest, "-x", policy.CurrentManifest+".minisig")
	if signature.Run() != nil {
		return errors.New("auto_current_signature_invalid")
	}
	return updateChannelState(policy, identity, "pending")
}

func runAcceptChannelState(args []string) {
	fs := flag.NewFlagSet("accept-channel-state", flag.ExitOnError)
	version := fs.String("version", "", "verified stable version")
	commit := fs.String("source-commit", "", "verified source commit")
	digest := fs.String("manifest-sha256", "", "exact signed manifest digest")
	_ = fs.Parse(args)
	policy := autoUpgradePolicy{OperationLockDirectory: "/var/lib/ultra-ansible", CurrentManifest: "/opt/ultra-recovery/release-manifest.json"}
	identity := &channelIdentity{Version: *version, SourceCommit: *commit, ManifestSHA256: *digest}
	if !validateChannelIdentity(identity) {
		exitOnErr("channel acceptance", errors.New("auto_channel_identity_invalid"))
		return
	}
	actual, err := sourceSHA(policy.CurrentManifest)
	if err != nil || actual != *digest {
		exitOnErr("channel acceptance", errors.New("auto_channel_manifest_conflict"))
		return
	}
	raw, readErr := os.ReadFile(policy.CurrentManifest)
	var actualManifest automationRelease
	if readErr != nil || json.Unmarshal(raw, &actualManifest) != nil || actualManifest.Version != identity.Version || actualManifest.SourceCommit != identity.SourceCommit {
		exitOnErr("channel acceptance", errors.New("auto_channel_manifest_conflict"))
		return
	}
	command := exec.Command("/usr/bin/minisign", "-V", "-p", "/etc/ultra-ansible/release-signing.pub", "-m", policy.CurrentManifest, "-x", policy.CurrentManifest+".minisig")
	if command.Run() != nil {
		exitOnErr("channel acceptance", errors.New("auto_channel_signature_invalid"))
		return
	}
	exitOnErr("channel acceptance", updateChannelState(policy, identity, "accepted"))
}
