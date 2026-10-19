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
	raw := []byte(
		`{"schema":1,"stage":"upgrade","mutator_dispatched":true,"forward_only":true,"former_targets_reimaged":true,"workers_fenced":true,"backup":"private-artifact","primary":"private-primary","manifest_sha256":"` + strings.Repeat(
			"a",
			64,
		) + `"}`,
	)
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
		if err := runRebuildNonDB(args, &output, rebuildTestNow); !errors.Is(
			err,
			errRebuildBlocked,
		) {
			t.Fatalf("expected blocked diagnosis, got %v", err)
		}
		var report rebuildDiagnosis
		if err := json.Unmarshal(output.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if report.Protocol != "ultra-rebuild-non-db-diagnosis-v1" || report.State != "blocked-evidence-not-collected" ||
			report.JournalSHA != digestSHA256(raw) ||
			report.GateReleased ||
			report.ExecutionSupported ||
			report.EvidenceCollected {
			t.Fatalf("diagnosis became authority: %+v", report)
		}
		if len(report.Blockers) != 8 {
			t.Fatalf("missing requirements: %v", report.Blockers)
		}
		if len(report.Requirements) != len(report.Blockers) || report.JournalPinMatched ||
			report.ArtifactsVerified ||
			len(report.Artifacts) != 0 {
			t.Fatalf("unexpected evidence authority: %+v", report)
		}
		for index, requirement := range report.Requirements {
			if requirement.Code != report.Blockers[index] || requirement.EvidenceKind == "" ||
				requirement.RequiredSource == "" || requirement.Binding == "" {
				t.Fatalf("requirement is not actionable: %+v", requirement)
			}
		}
		for _, requirement := range []string{"prior_target_manifest", "local_dispatch", "remote_mutator", "reimage_receipts",
			"primary_identity_and_target_exclusion", "backup_digest_primary_and_config_binding", "connectivity_and_authorization", "completion_and_retirement"} {
			if !strings.Contains(strings.Join(report.Blockers, " "), requirement) {
				t.Fatalf("missing requirement %s", requirement)
			}
		}
		if strings.Contains(output.String(), "private-") ||
			strings.Contains(output.String(), strings.Repeat("a", 64)) {
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

func TestRebuildDiagnoseArtifactIntakeRemainsBlockedAndDeterministic(t *testing.T) {
	root := t.TempDir()
	journal := []byte(
		`{"schema":1,"stage":"upgrade","mutator_dispatched":true,"forward_only":true}`,
	)
	journalPath := filepath.Join(root, "operation.json")
	if err := os.WriteFile(journalPath, journal, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{
		"diagnose",
		"--original-journal",
		journalPath,
		"--expected-journal-sha256",
		digestSHA256(journal),
	}
	var artifacts []string
	for _, requirement := range rebuildDiagnosticRequirements() {
		path := filepath.Join(root, requirement.EvidenceKind)
		// Even JSON claiming independent authority is only an opaque fingerprint.
		raw := []byte(
			`{"verified":true,"workers_fenced":true,"gate_released":true,"private":"hidden-content"}`,
		)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		artifacts = append(artifacts, "--artifact", requirement.EvidenceKind+"="+path)
	}
	var first []byte
	for iteration := 0; iteration < 2; iteration++ {
		var output bytes.Buffer
		if err := runRebuildNonDB(append(args, artifacts...), &output, rebuildTestNow); !errors.Is(
			err,
			errRebuildBlocked,
		) {
			t.Fatalf("intake authorized recovery: %v", err)
		}
		var report rebuildDiagnosis
		if err := json.Unmarshal(output.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if !report.JournalPinMatched || len(report.Artifacts) != 8 || len(report.Blockers) != 8 ||
			report.ArtifactsVerified || report.ExecutionSupported || report.GateReleased || report.EvidenceCollected {
			t.Fatalf("unverified intake became authority: %+v", report)
		}
		for _, artifact := range report.Artifacts {
			raw, err := os.ReadFile(filepath.Join(root, artifact.Kind))
			if err != nil || artifact.Verified || artifact.SHA256 != digestSHA256(raw) ||
				artifact.SizeBytes != len(raw) {
				t.Fatalf("artifact mismatch: %+v, %v", artifact, err)
			}
		}
		if strings.Contains(output.String(), root) ||
			strings.Contains(output.String(), "hidden-content") {
			t.Fatal("artifact path or contents leaked")
		}
		if iteration == 0 {
			first = append([]byte(nil), output.Bytes()...)
			// Reverse input order; output ordering remains canonical.
			for left, right := 1, len(artifacts)-1; left < right; left, right = left+2, right-2 {
				artifacts[left], artifacts[right] = artifacts[right], artifacts[left]
			}
		} else if !bytes.Equal(first, output.Bytes()) {
			t.Fatal("repeat intake changed report")
		}
	}
	got, err := os.ReadFile(journalPath)
	if err != nil || !bytes.Equal(got, journal) {
		t.Fatal("journal changed", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 9 {
		t.Fatal("intake wrote state", err)
	}
}

func TestRebuildDiagnoseArtifactIntakeRejectsUnsafeOrUnboundInputs(t *testing.T) {
	root := t.TempDir()
	journal := []byte(
		`{"schema":1,"stage":"upgrade","mutator_dispatched":true,"forward_only":true}`,
	)
	journalPath, artifactPath := filepath.Join(
		root,
		"operation.json",
	), filepath.Join(
		root,
		"artifact",
	)
	for _, path := range []string{journalPath, artifactPath} {
		if err := os.WriteFile(path, journal, 0600); err != nil {
			t.Fatal(err)
		}
	}
	publicPath, linkPath := filepath.Join(root, "public"), filepath.Join(root, "link")
	if err := os.WriteFile(publicPath, journal, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(artifactPath, linkPath); err != nil {
		t.Fatal(err)
	}
	base := []string{"diagnose", "--original-journal", journalPath}
	pin := []string{"--expected-journal-sha256", digestSHA256(journal)}
	cases := map[string][]string{
		"no pin":      {"--artifact", "historical-targets=" + artifactPath},
		"wrong pin":   {"--expected-journal-sha256", strings.Repeat("0", 64)},
		"invalid pin": {"--expected-journal-sha256", "invalid"},
		"wrong kind": append(
			append([]string{}, pin...),
			"--artifact",
			"operator-assertion="+artifactPath,
		),
		"relative": append(
			append([]string{}, pin...),
			"--artifact",
			"historical-targets=relative",
		),
		"duplicate": append(
			append([]string{}, pin...),
			"--artifact",
			"historical-targets="+artifactPath,
			"--artifact",
			"local-quiescence="+artifactPath,
		),
		"journal alias": append(
			append([]string{}, pin...),
			"--artifact",
			"historical-targets="+journalPath,
		),
		"public": append(
			append([]string{}, pin...),
			"--artifact",
			"historical-targets="+publicPath,
		),
		"symlink": append(
			append([]string{}, pin...),
			"--artifact",
			"historical-targets="+linkPath,
		),
		"missing": append(
			append([]string{}, pin...),
			"--artifact",
			"historical-targets="+filepath.Join(root, "missing"),
		),
	}
	tooMany := append([]string{}, pin...)
	for index := 0; index < 33; index++ {
		tooMany = append(tooMany, "--artifact", "historical-targets="+artifactPath)
	}
	cases["limit"] = tooMany
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			err := runRebuildNonDB(
				append(append([]string{}, base...), extra...),
				&output,
				rebuildTestNow,
			)
			if err == nil || errors.Is(err, errRebuildBlocked) || output.Len() != 0 {
				t.Fatalf("unsafe intake admitted: %v, %s", err, output.String())
			}
		})
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
			err := runRebuildNonDB(
				[]string{"diagnose", "--original-journal", path},
				&output,
				rebuildTestNow,
			)
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
		if err := runRebuildNonDB(args, &output, rebuildTestNow); err == nil ||
			errors.Is(err, errRebuildBlocked) ||
			output.Len() != 0 {
			t.Fatalf("accepted unsafe input or override: %v", args)
		}
	}
}
