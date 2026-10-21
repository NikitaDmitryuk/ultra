package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

type upgradeBaselineProof struct {
	Stage         string `json:"stage"`
	RequestSHA    string `json:"request_sha256"`
	Alias         string `json:"alias,omitempty"`
	Checkpoint    string `json:"checkpoint,omitempty"`
	CheckpointSHA string `json:"checkpoint_sha256,omitempty"`
}
type upgradeBaselineDescriptor struct {
	Schema      int                             `json:"schema"`
	Journal     string                          `json:"journal"`
	JournalSHA  string                          `json:"journal_sha256"`
	Manifest    string                          `json:"manifest"`
	ManifestSHA string                          `json:"manifest_sha256"`
	Bridge      upgradeBaselineProof            `json:"bridge"`
	Exits       map[string]upgradeBaselineProof `json:"exits"`
}
type upgradeBaselineInput struct {
	Descriptor    upgradeBaselineDescriptor `json:"descriptor"`
	Manifest      automationRelease         `json:"manifest"`
	RemoteRelease string                    `json:"remote_release"`
}
type upgradeBaselineResult struct {
	BridgeRelay automationRelease            `json:"bridge_relay"`
	Exits       map[string]automationRelease `json:"exits"`
}

// The descriptor selects evidence, never observed active hashes. Its local
// anchor is the surviving operator journal; the remote verifier independently
// proves successful component receipts and retained immutable release bytes.
func prepareUpgradeBaseline(path, directory string) (*upgradeBaselineInput, error) {
	if path == "" {
		if _, err := os.Lstat(filepath.Join(directory, "baseline.input.json")); !os.IsNotExist(err) {
			return nil, errors.New("upgrade_baseline_required_for_retry")
		}
		return nil, nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("upgrade_baseline_path_invalid")
	}
	if err := operatorPrivate(path, false); err != nil {
		return nil, err
	}
	raw, err := readBootstrapGenerationInput(path)
	if err != nil {
		return nil, err
	}
	var d upgradeBaselineDescriptor
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) != nil || decoder.Decode(new(any)) != io.EOF || d.Schema != 1 || len(d.Exits) == 0 || len(d.Exits) > 16 {
		return nil, errors.New("upgrade_baseline_descriptor_invalid")
	}
	hashPattern := regexp.MustCompile(`^[a-f0-9]{64}$`)
	for _, sum := range []string{d.JournalSHA, d.ManifestSHA, d.Bridge.RequestSHA, d.Bridge.CheckpointSHA} {
		if !hashPattern.MatchString(sum) {
			return nil, errors.New("upgrade_baseline_pin_invalid")
		}
	}
	for id, p := range d.Exits {
		if !regexp.MustCompile(`^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$`).MatchString(id) ||
			!bootstrapComponentAlias.MatchString(p.Alias) ||
			!hashPattern.MatchString(p.RequestSHA) ||
			p.Checkpoint != "" ||
			p.CheckpointSHA != "" {
			return nil, errors.New("upgrade_baseline_exit_invalid")
		}
	}
	for _, p := range append([]upgradeBaselineProof{d.Bridge}, baselineExitProofs(d.Exits)...) {
		if !filepath.IsAbs(p.Stage) || filepath.Clean(p.Stage) != p.Stage {
			return nil, errors.New("upgrade_baseline_stage_invalid")
		}
	}
	if !filepath.IsAbs(d.Bridge.Checkpoint) || filepath.Clean(d.Bridge.Checkpoint) != d.Bridge.Checkpoint || d.Bridge.Alias != "" {
		return nil, errors.New("upgrade_baseline_bridge_invalid")
	}
	readPinned := func(path, sum string) ([]byte, error) {
		if !filepath.IsAbs(path) {
			return nil, errors.New("upgrade_baseline_path_invalid")
		}
		if err := operatorPrivate(path, false); err != nil {
			return nil, err
		}
		b, e := readBootstrapGenerationInput(path)
		if e != nil {
			return nil, e
		}
		digest := sha256.Sum256(b)
		if hex.EncodeToString(digest[:]) != sum {
			return nil, errors.New("upgrade_baseline_local_pin_changed")
		}
		return b, nil
	}
	journal, err := readPinned(d.Journal, d.JournalSHA)
	if err != nil {
		return nil, err
	}
	var j struct {
		Schema      int    `json:"schema"`
		Commit      string `json:"commit"`
		Version     string `json:"version"`
		ManifestSHA string `json:"manifest_sha256"`
		Attempt     string `json:"remote_attempt"`
		Dispatched  bool   `json:"mutator_dispatched"`
	}
	if json.Unmarshal(journal, &j) != nil || j.Schema != 1 || !j.Dispatched || j.ManifestSHA != d.ManifestSHA ||
		!regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(j.Commit) ||
		!regexp.MustCompile(`^[a-f0-9]{16,64}$`).MatchString(j.Attempt) {
		return nil, errors.New("upgrade_baseline_journal_invalid")
	}
	manifestRaw, err := readPinned(d.Manifest, d.ManifestSHA)
	if err != nil {
		return nil, err
	}
	manifest, err := verifyAutomationRelease(filepath.Dir(d.Manifest), j.Version)
	if err != nil {
		return nil, err
	}
	if filepath.Base(d.Manifest) != "release-manifest.json" || manifest.SourceCommit != j.Commit {
		return nil, errors.New("upgrade_baseline_manifest_unbound")
	}
	input := &upgradeBaselineInput{
		Descriptor:    d,
		Manifest:      *manifest,
		RemoteRelease: "/var/lib/ultra-ansible/operator-inputs/manual-" + j.Commit + "-" + j.Attempt + "/release",
	}
	normalized, _ := json.Marshal(input)
	for name, data := range map[string][]byte{"baseline.input.json": normalized, "baseline.journal.json": journal, "baseline.manifest.json": manifestRaw} {
		if err = writeUpgradeInput(filepath.Join(directory, name), data); err != nil {
			return nil, err
		}
	}
	return input, nil
}
func baselineExitProofs(exits map[string]upgradeBaselineProof) []upgradeBaselineProof {
	result := []upgradeBaselineProof{}
	for _, p := range exits {
		result = append(result, p)
	}
	return result
}

func freezeUpgradeBaseline(
	input *upgradeBaselineInput,
	result upgradeBaselineResult,
	inspection upgradeInspection,
	target *automationRelease,
	directory string,
) error {
	if input == nil {
		return nil
	}
	if len(result.Exits) != len(inspection.Nodes) || len(input.Descriptor.Exits) != len(inspection.Nodes) {
		return errors.New("upgrade_baseline_topology_changed")
	}
	if err := compatibleAnsibleRelease(&result.BridgeRelay, target); err != nil {
		return err
	}
	for _, node := range inspection.Nodes {
		manifest, ok := result.Exits[node.ID]
		if !ok {
			return errors.New("upgrade_baseline_exit_missing")
		}
		raw, _ := json.Marshal(manifest)
		expected, _ := json.Marshal(input.Manifest)
		if !bytes.Equal(raw, expected) {
			return errors.New("upgrade_baseline_manifest_changed")
		}
		if err := compatibleAnsibleRelease(&manifest, target); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return writeUpgradeInput(filepath.Join(directory, "baseline.normalized.json"), raw)
}
