package main

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func bridgeReimageProofFixture(t *testing.T) (*recoveryBridgeReimage, []byte, retainedPrimaryRebuildInput) {
	in, fleet := bridgeReimageFleetFixture(t)
	fleet[1].Enabled = false
	fleet[2].State = "deleted"
	fleet[2].OccupiesSlot = false
	number, _ := new(big.Int).SetString(bridgePreflightCommit, 16)
	version := "v0.0." + number.String()
	legacy, _ := json.Marshal(
		bridgePreflightJournal{
			Schema:            1,
			Commit:            bridgePreflightCommit,
			Version:           version,
			Backup:            "install.config.before-" + version + "-123",
			PreviousSHA:       strings.Repeat("a", 64),
			ConfigSHA:         strings.Repeat("b", 64),
			Stage:             "upgrade",
			MutatorDispatched: true,
			TransportBinding:  strings.Repeat("c", 64),
			ManifestSHA:       strings.Repeat("d", 64),
			Attempt:           strings.Repeat("e", 64),
			StagedConfigSHA:   strings.Repeat("f", 64),
			Architecture:      runtime.GOARCH,
			SecretsSource:     "installed-runtime",
			ConfigProjection:  "upgrade-v2",
		},
	)
	proof := &recoveryBridgeReimage{
		Fleet:           fleet,
		Acknowledgement: bridgeReimageAcknowledgement,
		OldConfig:       []byte("canonical bytes"),
		SourceSpec:      []byte("source bytes"),
		LegacyJournal:   legacy,
	}
	descriptor := recoveryInputSnapshot{
		Schema: 1,
		Request: recoveryPreparationRequest{
			RetainedFenceSHA256: in.RetainedExit.FenceSHA256,
			LegacyJournalSHA256: digestSHA256(legacy),
			ToolsManifestSHA256: strings.Repeat("d", 64),
		},
	}
	proof.Descriptor, _ = json.Marshal(descriptor)
	j := map[string]any{
		"schema":                            1,
		"supervised_deploy":                 true,
		"mutator_dispatched":                true,
		"adopt":                             false,
		"forward_only":                      false,
		"stage":                             "upgrade",
		"config_sha256":                     digestSHA256(proof.OldConfig),
		"manifest_sha256":                   strings.Repeat("d", 64),
		"remote_attempt":                    strings.Repeat("a", 64),
		"transport_binding":                 strings.Repeat("b", 64),
		"preparation_sha256":                strings.Repeat("c", 64),
		"preparation_descriptor_sha256":     digestSHA256(proof.Descriptor),
		"preparation_source_spec_sha256":    digestSHA256(proof.SourceSpec),
		"preparation_legacy_journal_sha256": digestSHA256(legacy),
		"preparation_source_archive":        "recovery-source-" + digestSHA256(legacy),
	}
	raw, _ := json.Marshal(j)
	in.JournalSHA256 = digestSHA256(raw)
	return proof, raw, in
}
func TestBridgeReimageProofRejectsMixedAuthority(t *testing.T) {
	for _, scenario := range []string{"valid", "no-ack", "old-config", "source", "legacy", "descriptor", "journal", "wrong-fence", "two-host-mode", "missing-exit", "partial-fleet", "live-dynamic"} {
		t.Run(scenario, func(t *testing.T) {
			proof, journal, in := bridgeReimageProofFixture(t)
			switch scenario {
			case "no-ack":
				proof.Acknowledgement = ""
			case "old-config":
				proof.OldConfig = []byte("new")
			case "source":
				proof.SourceSpec = []byte("new")
			case "legacy":
				proof.LegacyJournal = []byte("new")
			case "descriptor":
				proof.Descriptor = []byte("new")
			case "journal":
				journal = append(journal, ' ')
			case "wrong-fence":
				in.RetainedExit.FenceSHA256 = strings.Repeat("f", 64)
			case "two-host-mode":
				in.BridgeOnly = false
			case "missing-exit":
				in.RetainedExit = nil
			case "live-dynamic":
				proof.Fleet[1].Enabled = true
				proof.Fleet[2].State = "ready"
				proof.Fleet[2].OccupiesSlot = true
			case "partial-fleet":
				proof.Fleet = proof.Fleet[1:]
			}
			if err := validateRecoveryBridgeReimage(proof, journal, in); (err == nil) != (scenario == "valid") {
				t.Fatalf("%s: %v", scenario, err)
			}
		})
	}
}
func TestBridgeReimageProviderRejectsUnregisteredInstances(t *testing.T) {
	p := &installplan.InstallPlan{}
	p.Bridge.Address = "192.0.2.1"
	for _, row := range []providerCensusInstance{{"registered", "192.0.2.20", true}, {"static", "192.0.2.1", true}, {"unknown", "192.0.2.99", true}} {
		err := verifyBridgeReimageProviderScope(providerCensusReceipt{Instances: []providerCensusInstance{row}}, p, []string{"registered"})
		if (err != nil) != (row.ID == "unknown") {
			t.Fatal("unknown live target admitted")
		}
	}
}
func TestBridgeReimageGenesisCrashResumeAndForeignLifecycle(t *testing.T) {
	for _, scenario := range []string{"fresh", "crash-after-marker", "foreign-lifecycle", "wrong-fence"} {
		t.Run(scenario, func(t *testing.T) {
			f := preparationAdmissionFixture(t)
			f.proof.BridgeGenesis = strings.Repeat("d", 64)
			f.proof.ExitFenceSHA256 = strings.Repeat("e", 64)
			if scenario != "foreign-lifecycle" {
				if err := os.Remove(filepath.Join(f.state, "lifecycle.json")); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "fresh" {
				if err := os.Remove(filepath.Join(f.state, "operator/infrastructure.lock")); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "crash-after-marker" {
				raw, _ := json.Marshal(
					map[string]string{"protocol": "ultra-bridge-reimage-genesis-v1", "binding_sha256": f.proof.BridgeGenesis},
				)
				if err := os.WriteFile(filepath.Join(f.state, "bridge-reimage-genesis.json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "wrong-fence" {
				f.proof.FenceSHA256 = strings.Repeat("f", 64)
			}
			lease, err := startRecoveryPreparationAdmission(f.command(t, "seal"), "seal")
			good := scenario == "fresh" || scenario == "crash-after-marker"
			if (err == nil) != good {
				t.Fatalf("genesis: %v", err)
			}
			if !good {
				return
			}
			if err = lease.recheck(); err != nil {
				t.Fatal(err)
			}
			lease.close()
			before, _ := os.ReadFile(filepath.Join(f.state, "lifecycle.json"))
			lease, err = startRecoveryPreparationAdmission(f.command(t, "validate"), "validate")
			if err != nil {
				t.Fatal(err)
			}
			lease.close()
			after, _ := os.ReadFile(filepath.Join(f.state, "lifecycle.json"))
			if string(before) != string(after) {
				t.Fatal("validation rewrote genesis")
			}
		})
	}
}

func TestBridgeReimageRetirementCannotRewriteHistoricalScope(t *testing.T) {
	for _, scenario := range []string{"valid", "missing-receipt", "wrong-binding", "wrong-operation", "not-deleted", "wrong-count"} {
		t.Run(scenario, func(t *testing.T) {
			_, fleet := bridgeReimageFleetFixture(t)
			binding := strings.Repeat("b", 64)
			fleet[1].Enabled = false
			fleet[2].State = "deleted"
			fleet[2].Phase = "cleanup"
			fleet[2].OccupiesSlot = false
			fleet[2].RetirementBinding = binding
			receipt := map[string]any{
				"protocol":        "ultra-provider-absence-retirement-v1",
				"binding_sha256":  binding,
				"deletion_sha256": strings.Repeat("a", 64),
				"operation_id":    fleet[2].ID,
				"exit_id":         fleet[2].ExitID,
				"instance_id":     fleet[2].InstanceID,
				"exit_rows":       1,
				"operation_rows":  1,
				"route_rows":      1,
				"event_rows":      1,
			}
			switch scenario {
			case "wrong-binding":
				receipt["binding_sha256"] = strings.Repeat("c", 64)
			case "wrong-operation":
				receipt["operation_id"] = fleet[0].ID
			case "not-deleted":
				fleet[2].State = "ready"
			case "wrong-count":
				receipt["exit_rows"] = 2
			}
			raw, _ := json.Marshal(receipt)
			if scenario == "missing-receipt" {
				raw = nil
			}
			err := validateBridgeReimageRetirement(&recoveryBridgeReimage{Fleet: fleet, Retirement: raw})
			if (err == nil) != (scenario == "valid") {
				t.Fatalf("retirement: %v", err)
			}
		})
	}
}

func TestBridgeReimageExitAdmissionPreflightRejectsForeignWithoutWriting(t *testing.T) {
	for _, scenario := range []string{"absent", "same", "foreign", "symlink"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "admission.json")
			admission := recoveryPreparationAdmission{
				Protocol:               "ultra-recovery-preparation-admission-v1",
				Phase:                  "sealed",
				FenceSHA256:            strings.Repeat("a", 64),
				BaselineManifestSHA256: strings.Repeat("b", 64),
				ConfigSHA256:           strings.Repeat("c", 64),
				ExitFenceSHA256:        strings.Repeat("d", 64),
				BridgeGenesis:          strings.Repeat("e", 64),
			}
			raw, _ := json.Marshal(admission)
			if scenario != "absent" {
				saved := raw
				if scenario == "foreign" {
					saved = []byte(`{"phase":"sealed","protocol":"foreign"}`)
				}
				if err := os.WriteFile(path, saved, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "symlink" {
				if err := os.Rename(path, path+".target"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".target", path); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(path)
			program := strings.ReplaceAll(
				bridgeReimageExitAdmissionPreflight,
				"Path('/var/lib/ultra-ansible/recovery-preparation-admission.json')",
				"Path("+fmtPython(path)+")",
			)
			program = strings.ReplaceAll(program, "for parent in path.parents:", "for parent in [path.parent]:")
			program = strings.ReplaceAll(program, "s.st_uid==0", "s.st_uid==os.geteuid()")
			command := exec.Command("python3", "-c", program, base64.StdEncoding.EncodeToString(raw))
			err := command.Run()
			if (err == nil) != (scenario == "absent" || scenario == "same") {
				t.Fatalf("preflight %s: %v", scenario, err)
			}
			after, _ := os.ReadFile(path)
			if string(before) != string(after) {
				t.Fatal("preflight wrote admission")
			}
			if scenario == "absent" {
				if _, e := os.Lstat(path); !os.IsNotExist(e) {
					t.Fatal("preflight created admission")
				}
			}
		})
	}
}
