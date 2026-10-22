package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestRecoveryPreparationRequiresExplicitSealOnly(t *testing.T) {
	var output bytes.Buffer
	for _, args := range [][]string{nil, {"--seal-only"}, {"--seal-only", "--state-dir", "relative"}} {
		if runRecoveryPreparation(args, &output) == nil {
			t.Fatal("invalid preparation accepted")
		}
	}
	if output.Len() != 0 {
		t.Fatal("invalid preparation published success")
	}
}

func TestRecoveryPreparationRequiresOriginalCompleteBaseline(t *testing.T) {
	_, paths := reconcileFixture(t)
	// A genuine succeeded retained execute receipt alone cannot replace the
	// independently verified original release baseline (fixture has no release).
	_, err := loadRecoveryPreparationInputs(paths[0], paths[1], paths[2], paths[3])
	if err == nil || err.Error() != "recovery_preparation_original_baseline_incomplete" {
		t.Fatalf("missing baseline: %v", err)
	}
}

func TestRecoveryPreparationAdmissionRejectsMalformedDigests(t *testing.T) {
	base := recoveryPreparationAdmission{
		"", "",
		"ultra-recovery-preparation-admission-v1",
		strings.Repeat("a", 64),
		strings.Repeat("b", 64),
		strings.Repeat("c", 64),
		"sealed",
	}
	if !base.valid() {
		t.Fatal("fixture invalid")
	}
	for i := 0; i < 3; i++ {
		bad := base
		switch i {
		case 0:
			bad.FenceSHA256 = strings.Repeat("z", 64)
		case 1:
			bad.BaselineManifestSHA256 = strings.Repeat("z", 64)
		case 2:
			bad.ConfigSHA256 = strings.Repeat("z", 64)
		}
		if bad.valid() {
			t.Fatal("length-only digest accepted")
		}
	}
}

func TestRecoveryPreparationReadinessRequiresFreshIndependentControllerProof(t *testing.T) {
	for _, raw := range []string{`{}`, `{"verified":true,"ready":true,"independent":false,"reasons":[]}`, `{"verified":true,"ready":true,"independent":true,"reasons":["backup_stale"]}`, `{"verified":true,"ready":true,"independent":true}`, `{"verified":true,"verified":false,"ready":true,"independent":true,"reasons":[]}`} {
		if _, err := validateRecoveryPreparationReadiness([]byte(raw)); err == nil {
			t.Fatalf("unproven readiness accepted: %s", raw)
		}
	}
	if _, err := validateRecoveryPreparationReadiness([]byte(`{"verified":true,"ready":true,"independent":true,"reasons":[]}`)); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryPreparationTerminalReceiptBindsExactRequestAndPhase(t *testing.T) {
	r := recoveryPreparationRequest{StateDirectory: t.TempDir(), Protocol: "ultra-recovery-preparation-request-v1"}
	if err := os.Chmod(r.StateDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	receipt := recoveryPreparationPhaseReceipt{
		"ultra-recovery-preparation-phase-v1",
		r.digest(),
		"tools_staged",
		123,
		true,
		map[string]any{"verified": true},
	}
	raw, _ := json.Marshal(receipt)
	if err := publishRetainedReconcile(preparationPhasePath(r, "tools_staged", ""), raw); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecoveryPreparationPhase(r, "tools_staged"); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecoveryPreparationPhase(r, "monitor_initialized"); err == nil {
		t.Fatal("stage receipt accepted as monitor proof")
	}
	changed := r
	changed.ToolsManifestSHA256 = strings.Repeat("b", 64)
	if _, err := readRecoveryPreparationPhase(changed, "tools_staged"); err == nil {
		t.Fatal("different request reused terminal proof")
	}
	if err := publishRetainedReconcile(preparationPhasePath(r, "tools_staged", ""), []byte(`{}`)); err == nil {
		t.Fatal("terminal evidence overwritten")
	}
}
