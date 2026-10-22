package main

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func bridgePreflightFixture(t *testing.T) (string, *installplan.InstallPlan, string, *automationRelease) {
	t.Helper()
	directory, p, release, manifest := localPreflightFixture(t)
	manifest.SourceCommit = bridgePreflightCommit
	if err := os.Remove(filepath.Join(directory, "runtime-use.json")); err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(directory)
	writeForwardJSON(t, filepath.Join(directory, "execution-mode.json"), frozenExecution{
		Schema: 1, Local: true, Target: p.Bridge.SSHHost + "|" + p.Bridge.Address,
		LockDirectory: root, OperatorDirectory: filepath.Join(root, "operator"), BootstrapEngine: "components-v1"})
	writeForwardJSON(t, filepath.Join(directory, "readiness-diagnostic-123.json"), map[string]string{
		"stage": "Wait without discovery or private topology inspection", "node": "bridge", "code": "task_failed"})
	return directory, p, release, manifest
}

func TestBridgePreflightRequiresExactAuditedStageProtocol(t *testing.T) {
	directory, p, release, manifest := bridgePreflightFixture(t)
	if err := verifyBridgePreflightOperation(directory, p, release, manifest); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"activate", "lifecycle-applying-1", "inspect", "runtime-use.json", "unknown"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory, name)
			if err := os.WriteFile(path, nil, 0600); err != nil {
				t.Fatal(err)
			}
			defer os.Remove(path) //nolint:errcheck
			if verifyBridgePreflightOperation(directory, p, release, manifest) == nil {
				t.Fatal("extra stage accepted")
			}
		})
	}
	// Neither adapter is a fallback for the other's execution shape.
	if verifyLocalPreflightOperation(directory, p, release, manifest) == nil {
		t.Fatal("historical adapter broadened")
	}
	manifest.SourceCommit = localPreflightCommit
	if verifyBridgePreflightOperation(directory, p, release, manifest) == nil {
		t.Fatal("unaudited source accepted")
	}
}

func TestBridgePreflightRejectsChangedEvidence(t *testing.T) {
	for _, name := range []string{"operator-plan.json", "execution-mode.json", "readiness-diagnostic-123.json"} {
		t.Run(name, func(t *testing.T) {
			directory, p, release, manifest := bridgePreflightFixture(t)
			if err := os.WriteFile(filepath.Join(directory, name), []byte(`{}`), 0600); err != nil {
				t.Fatal(err)
			}
			if verifyBridgePreflightOperation(directory, p, release, manifest) == nil {
				t.Fatal("changed evidence accepted")
			}
		})
	}
}

func TestBridgePreflightJournalPinsExactHistoricalClass(t *testing.T) {
	commit, _ := new(big.Int).SetString(bridgePreflightCommit, 16)
	version := "v0.0." + commit.String()
	j := bridgePreflightJournal{Schema: 1, Commit: bridgePreflightCommit, Version: version,
		Backup: "install.config.before-" + version + "-123", PreviousSHA: strings.Repeat("a", 64),
		ConfigSHA: strings.Repeat("b", 64), Stage: "upgrade", MutatorDispatched: true,
		TransportBinding: strings.Repeat("c", 64), ManifestSHA: strings.Repeat("d", 64),
		Attempt: strings.Repeat("e", 64), StagedConfigSHA: strings.Repeat("f", 64),
		Architecture: runtime.GOARCH, SecretsSource: "installed-runtime", ConfigProjection: "upgrade-v2"}
	raw, _ := json.Marshal(j)
	if _, err := parseBridgePreflightJournal(raw); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"commit", "version", "stage", "secrets_source", "config_projection", "remote_attempt", "adopt"} {
		t.Run(field, func(t *testing.T) {
			var changed map[string]any
			_ = json.Unmarshal(raw, &changed)
			delete(changed, field)
			data, _ := json.Marshal(changed)
			if _, err := parseBridgePreflightJournal(data); err == nil {
				t.Fatal("incomplete historical journal accepted")
			}
		})
	}
	for _, change := range []func(*bridgePreflightJournal){
		func(j *bridgePreflightJournal) { j.Commit = localPreflightCommit },
		func(j *bridgePreflightJournal) { j.ForwardOnly = true },
		func(j *bridgePreflightJournal) { j.Adopt = true },
		func(j *bridgePreflightJournal) { j.Stage = "status" },
		func(j *bridgePreflightJournal) { j.SecretsSource = "canonical" },
		func(j *bridgePreflightJournal) { j.StagedConfigSHA = "" },
	} {
		changed := j
		change(&changed)
		data, _ := json.Marshal(changed)
		if _, err := parseBridgePreflightJournal(data); err == nil {
			t.Fatal("different historical protocol accepted")
		}
	}
}
