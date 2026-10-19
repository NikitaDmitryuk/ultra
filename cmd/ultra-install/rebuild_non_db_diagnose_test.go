package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRebuildDiagnoseForwardUpgradeReadOnly(t *testing.T) {
	root := t.TempDir()
	journalPath := filepath.Join(root, "operation.json")
	// Operator assertions, release digests and a backup filename do not establish
	// any independently collected evidence, even for already reimaged machines.
	raw := []byte(`{"schema":1,"stage":"upgrade","mutator_dispatched":true,"forward_only":true,"former_targets_reimaged":true,"workers_fenced":true,"backup":"private-artifact","primary":"private-primary","manifest_sha256":"` + strings.Repeat("a", 64) + `"}`)
	lockPath := filepath.Join(root, "deploy.lock")
	for _, path := range []string{journalPath, lockPath} {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	before, err := os.Stat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	args := []string{"diagnose", "--original-journal", journalPath}
	for iteration := 0; iteration < 2; iteration++ {
		output.Reset()
		if err := runRebuildNonDB(args, &output, rebuildTestNow); !errors.Is(err, errRebuildBlocked) {
			t.Fatalf("expected blocked diagnosis, got %v", err)
		}
		var report rebuildDiagnosis
		if err := json.Unmarshal(output.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if report.Protocol != "ultra-rebuild-non-db-diagnosis-v1" || report.State != "blocked-evidence-not-collected" ||
			report.JournalSHA != digestSHA256(raw) || report.GateReleased || report.ExecutionSupported || report.EvidenceCollected {
			t.Fatalf("diagnosis became authority: %+v", report)
		}
		if len(report.Blockers) != 8 {
			t.Fatalf("missing requirements: %v", report.Blockers)
		}
		for _, requirement := range []string{"prior_target_manifest", "local_dispatch", "remote_mutator", "reimage_receipts",
			"primary_identity_and_target_exclusion", "backup_digest_primary_and_config_binding", "connectivity_and_authorization", "completion_and_retirement"} {
			if !strings.Contains(strings.Join(report.Blockers, " "), requirement) {
				t.Fatalf("missing requirement %s", requirement)
			}
		}
		if strings.Contains(output.String(), "private-") || strings.Contains(output.String(), strings.Repeat("a", 64)) {
			t.Fatal("journal contents leaked")
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 2 {
		t.Fatalf("diagnosis wrote state: %v, %v", entries, err)
	}
	for _, path := range []string{journalPath, lockPath} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("input changed: %s, %v", path, err)
		}
	}
	after, err := os.Stat(lockPath)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("lock replaced", err)
	}
}

func TestRebuildDiagnoseRejectsInvalidScope(t *testing.T) {
	for name, raw := range map[string]string{
		"adoption":       `{"schema":1,"stage":"adoption_apply","mutator_dispatched":true,"forward_only":true}`,
		"not dispatched": `{"schema":1,"stage":"upgrade","mutator_dispatched":false,"forward_only":true}`,
		"not forward":    `{"schema":1,"stage":"upgrade","mutator_dispatched":true,"forward_only":false}`,
		"missing":        `{"schema":1,"stage":"upgrade","mutator_dispatched":true}`,
		"null":           `null`,
		"duplicate":      `{"schema":1,"schema":1,"stage":"upgrade","mutator_dispatched":true,"forward_only":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "operation.json")
			if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			err := runRebuildNonDB([]string{"diagnose", "--original-journal", path}, &output, rebuildTestNow)
			if err == nil || errors.Is(err, errRebuildBlocked) || output.Len() != 0 {
				t.Fatalf("invalid journal became diagnosis: %v %s", err, output.String())
			}
		})
	}
}

func TestRebuildDiagnoseRejectsUnsafeInputAndOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operation.json")
	if err := os.WriteFile(path, []byte(`{"schema":1,"stage":"upgrade","mutator_dispatched":true,"forward_only":true}`), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"diagnose", "--original-journal", path},
		{"diagnose", "--original-journal", "operation.json"},
		{"diagnose", "--original-journal", path, "--force"},
		{"diagnose", "--original-journal", path, "--former-targets-reimaged"},
	} {
		var output bytes.Buffer
		if err := runRebuildNonDB(args, &output, rebuildTestNow); err == nil || errors.Is(err, errRebuildBlocked) || output.Len() != 0 {
			t.Fatalf("accepted unsafe input or override: %v", args)
		}
	}
}
