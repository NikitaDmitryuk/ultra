package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func baselineFixture(t *testing.T) (upgradeBaselineDescriptor, string, string) {
	t.Helper()
	root := githubPrivateStage(t)
	release := filepath.Join(root, "release")
	if err := os.Mkdir(release, 0700); err != nil {
		t.Fatal(err)
	}
	files, _, _ := githubFixture(t)
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(release, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	manifestPath := filepath.Join(release, "release-manifest.json")
	manifestSHA, err := sourceSHA(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(root, "operation.json")
	data, _ := json.Marshal(map[string]any{"schema": 1, "commit": strings.Repeat("a", 40), "version": "v2.5.0", "manifest_sha256": manifestSHA, "remote_attempt": strings.Repeat("c", 64), "mutator_dispatched": true})
	if err = os.WriteFile(journal, data, 0600); err != nil {
		t.Fatal(err)
	}
	id := "11111111-2222-3333-4444-555555555555"
	descriptor := upgradeBaselineDescriptor{Schema: 1, Journal: journal, JournalSHA: fmt.Sprintf("%x", sha256.Sum256(data)), Manifest: manifestPath, ManifestSHA: manifestSHA,
		Bridge: upgradeBaselineProof{Stage: "/root/jobs/rollback", RequestSHA: strings.Repeat("d", 64), Checkpoint: "/var/lib/ultra-ansible/adoption/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/checkpoint.json", CheckpointSHA: strings.Repeat("e", 64)},
		Exits:  map[string]upgradeBaselineProof{id: {Stage: "/root/jobs/bootstrap-exit_0", RequestSHA: strings.Repeat("f", 64), Alias: "exit_0"}}}
	path := filepath.Join(root, "baseline.json")
	directory := filepath.Join(root, "upgrade")
	if err = os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return descriptor, path, directory
}
func writeBaselineFixture(t *testing.T, path string, d upgradeBaselineDescriptor) {
	t.Helper()
	raw, _ := json.Marshal(d)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeBaselineLocalJournalAndBundleAreBoundAndFrozen(t *testing.T) {
	d, path, directory := baselineFixture(t)
	writeBaselineFixture(t, path, d)
	input, err := prepareUpgradeBaseline(path, directory)
	if err != nil {
		t.Fatal(err)
	}
	if input.RemoteRelease != "/var/lib/ultra-ansible/operator-inputs/manual-"+strings.Repeat("a", 40)+"-"+strings.Repeat("c", 64)+"/release" {
		t.Fatal("journal attempt not bound to retained bundle")
	}
	for _, name := range []string{"baseline.input.json", "baseline.journal.json", "baseline.manifest.json"} {
		if err := operatorPrivate(filepath.Join(directory, name), false); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = prepareUpgradeBaseline(path, directory); err != nil {
		t.Fatal(err)
	}
	if _, err = prepareUpgradeBaseline("", directory); err == nil {
		t.Fatal("retry omitted frozen baseline")
	}
	d.Exits["11111111-2222-3333-4444-555555555555"] = upgradeBaselineProof{Stage: "/root/other-stage", RequestSHA: strings.Repeat("f", 64), Alias: "exit_0"}
	writeBaselineFixture(t, path, d)
	if _, err = prepareUpgradeBaseline(path, directory); err == nil {
		t.Fatal("changed frozen receipt selection accepted")
	}
}

func TestUpgradeBaselineRejectsUnboundOrIncompleteEvidence(t *testing.T) {
	for _, change := range []string{"journal-pin", "not-dispatched", "manifest-pin", "asset-drift", "unknown-field", "private-mode", "stage-path", "exit-role"} {
		t.Run(change, func(t *testing.T) {
			d, path, directory := baselineFixture(t)
			writeBaselineFixture(t, path, d)
			switch change {
			case "journal-pin":
				d.JournalSHA = strings.Repeat("1", 64)
				writeBaselineFixture(t, path, d)
			case "not-dispatched":
				raw, _ := os.ReadFile(d.Journal)
				var j map[string]any
				_ = json.Unmarshal(raw, &j)
				j["mutator_dispatched"] = false
				raw, _ = json.Marshal(j)
				_ = os.WriteFile(d.Journal, raw, 0600)
				d.JournalSHA = fmt.Sprintf("%x", sha256.Sum256(raw))
				writeBaselineFixture(t, path, d)
			case "manifest-pin":
				d.ManifestSHA = strings.Repeat("1", 64)
				writeBaselineFixture(t, path, d)
			case "asset-drift":
				_ = os.WriteFile(filepath.Join(filepath.Dir(d.Manifest), "ultra-relay-linux-amd64"), []byte("untrusted"), 0600)
			case "unknown-field":
				raw, _ := os.ReadFile(path)
				raw = append(raw[:len(raw)-1], []byte(",\"observed_sha256\":\"untrusted\"}")...)
				_ = os.WriteFile(path, raw, 0600)
			case "private-mode":
				_ = os.Chmod(path, 0644)
			case "stage-path":
				d.Bridge.Stage = "/root/jobs/../rollback"
				writeBaselineFixture(t, path, d)
			case "exit-role":
				p := d.Exits["11111111-2222-3333-4444-555555555555"]
				p.Alias = "bridge"
				d.Exits["11111111-2222-3333-4444-555555555555"] = p
				writeBaselineFixture(t, path, d)
			}
			if _, err := prepareUpgradeBaseline(path, directory); err == nil {
				t.Fatal("invalid baseline accepted")
			}
		})
	}
}

func TestUpgradeBaselineNormalizedExitsMustEqualFrozenTopologyAndManifest(t *testing.T) {
	d, path, directory := baselineFixture(t)
	writeBaselineFixture(t, path, d)
	input, err := prepareUpgradeBaseline(path, directory)
	if err != nil {
		t.Fatal(err)
	}
	id := "11111111-2222-3333-4444-555555555555"
	inspection := upgradeInspection{}
	inspection.Nodes = append(inspection.Nodes, struct {
		ID      string `json:"id"`
		Address string `json:"address"`
		Pins    string `json:"pins"`
	}{ID: id})
	result := upgradeBaselineResult{BridgeRelay: input.Manifest, Exits: map[string]automationRelease{id: input.Manifest}}
	if err = freezeUpgradeBaseline(input, result, inspection, &input.Manifest, directory); err != nil {
		t.Fatal(err)
	}
	altered := input.Manifest
	altered.Assets = append([]struct {
		Name string `json:"name"`
		SHA  string `json:"sha256"`
		Size int64  `json:"size"`
	}{}, altered.Assets...)
	altered.Assets[0].SHA = strings.Repeat("b", 64)
	result.Exits[id] = altered
	if freezeUpgradeBaseline(input, result, inspection, &input.Manifest, directory) == nil {
		t.Fatal("changed per-host manifest accepted")
	}
	delete(result.Exits, id)
	if freezeUpgradeBaseline(input, result, inspection, &input.Manifest, directory) == nil {
		t.Fatal("missing frozen exit accepted")
	}
}
