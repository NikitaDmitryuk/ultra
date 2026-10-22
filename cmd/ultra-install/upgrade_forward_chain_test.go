package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func cloneForwardMap(t *testing.T, v map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func writeChainStage(
	t *testing.T,
	stage, operation string,
	inventory, variables, result map[string]any,
	diagnostic *deployansible.Diagnostic,
) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(stage, "bundle"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "bundle", "controller.py"), []byte("prior-controller-source"), 0600); err != nil {
		t.Fatal(err)
	}
	writeForwardJSON(t, filepath.Join(stage, "request.json"), map[string]any{"inventory": inventory, "variables": variables})
	raw, err := os.ReadFile(filepath.Join(stage, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	job := map[string]any{
		"schema_version": 1,
		"operation":      operation,
		"request_sha256": digestSHA256(raw),
		"binary_sha256":  digestSHA256(raw),
	}
	writeForwardJSON(t, filepath.Join(stage, "job.json"), job)
	if diagnostic == nil {
		job["state"] = "succeeded"
		job["result"] = result
		writeForwardJSON(t, filepath.Join(stage, "result.json"), result)
	} else {
		job["state"] = "failed"
		job["code"] = "ansible_failed"
		job["exit_code"] = 2
		job["diagnostic"] = diagnostic
		writeForwardJSON(t, filepath.Join(stage, "diagnostic.json"), diagnostic)
	}
	job["started_at"] = 1
	job["finished_at"] = 2
	writeForwardJSON(t, filepath.Join(stage, "receipt.json"), job)
}

type chainFixture struct {
	proof           forwardUpgradeJournal
	old             forwardOldOperation
	root, directory string
	prior           forwardPriorCandidate
	deps            forwardHandoffDeps
	events          []string
	held            bool
	ledger          []byte
}

func forwardChainFixture(t *testing.T) *chainFixture {
	t.Helper()
	proof, old, root, directory, prior := forwardPriorRecoveryFixture(t)
	f := &chainFixture{proof: proof, old: old, root: root, directory: directory, prior: prior}
	children := old.Inventory["all"].(map[string]any)["children"].(map[string]any)
	exits := children["exits"].(map[string]any)["hosts"].(map[string]any)
	ids := []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"}
	exits["exit_a"].(map[string]any)["ultra_exit_id"] = ids[0]
	exits["exit_b"].(map[string]any)["ultra_exit_id"] = ids[1]
	// Upgrade the old lightweight fixture to a real UUID-bound observed fleet.
	raw, err := os.ReadFile(filepath.Join(old.Directory, "activate", "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var request map[string]any
	if err := json.Unmarshal(raw, &request); err != nil {
		t.Fatal(err)
	}
	request["inventory"] = old.Inventory
	writeForwardJSON(t, filepath.Join(old.Directory, "activate", "request.json"), request)
	raw, err = os.ReadFile(filepath.Join(old.Directory, "activate", "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"job.json", "receipt.json"} {
		writeForwardJSON(
			t,
			filepath.Join(old.Directory, "activate", name),
			map[string]any{
				"schema_version": 1,
				"operation":      "upgrade",
				"request_sha256": digestSHA256(raw),
				"binary_sha256":  digestSHA256(raw),
			},
		)
	}
	intent, err := loadForwardIntent(filepath.Join(prior.Directory, "forward-handoff.json"))
	if err != nil {
		t.Fatal(err)
	}
	writeChainStage(
		t,
		intent.Stage,
		"drain-upgrade-workers",
		old.Inventory,
		forwardDrainVariables(root, old.ID, lifecycleID(prior.Directory)),
		map[string]any{"verified": true, "old_id": old.ID, "new_id": lifecycleID(prior.Directory)},
		nil,
	)
	updated, err := forwardDrainIntent(proof, old, root, prior.Directory, intent.Stage)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveForwardIntent(prior.Directory, updated); err != nil {
		t.Fatal(err)
	}
	inputs, err := filepath.Glob(filepath.Join(root, "operator-inputs", "manual-*2-*", "install.config"))
	if err != nil || len(inputs) != 1 {
		t.Fatal("prior input", inputs, err)
	}
	configRaw, err := os.ReadFile(inputs[0])
	if err != nil {
		t.Fatal(err)
	}
	configRaw = append(configRaw, []byte("DNS_PROVIDER=vultr\nDNS_ZONE=example.com\n")...)
	if err := os.WriteFile(inputs[0], configRaw, 0600); err != nil {
		t.Fatal(err)
	}
	plan, err := installplan.LoadConfig(inputs[0])
	if err != nil {
		t.Fatal(err)
	}
	release := filepath.Join(filepath.Dir(inputs[0]), "release")
	if err := installplan.ValidatePlan(plan); err != nil {
		t.Fatal(err)
	}
	planSHA, err := operatorPlanDigest(plan, release)
	if err != nil {
		t.Fatal(err)
	}
	writeForwardJSON(t, filepath.Join(prior.Directory, "operator-plan.json"), map[string]string{"plan_sha256": planSHA})
	tools := []string{
		"recovery.py",
		"monitor.py",
		"heartbeat.py",
		"reconcile.py",
		"live_tools.py",
		"ultra-recovery-backup.service",
		"ultra-recovery-backup.timer",
	}
	if err := os.Mkdir(filepath.Join(prior.Directory, "recovery-bundle"), 0700); err != nil {
		t.Fatal(err)
	}
	archive, err := os.OpenFile(filepath.Join(release, "ultra-recovery.tar.gz"), os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(archive)
	tw := tar.NewWriter(gz)
	for _, name := range tools {
		data := []byte("fixture:" + name)
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(prior.Directory, "recovery-bundle", name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := os.ReadFile(filepath.Join(release, "release-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(release, "ultra-recovery.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range manifest["assets"].([]any) {
		asset := entry.(map[string]any)
		if asset["name"] == "ultra-recovery.tar.gz" {
			asset["sha256"] = digestSHA256(data)
			asset["size"] = len(data)
		}
	}
	writeForwardJSON(t, filepath.Join(release, "release-manifest.json"), manifest)
	journalRaw, err := os.ReadFile(prior.Journal)
	if err != nil {
		t.Fatal(err)
	}
	var journal map[string]any
	if err := json.Unmarshal(journalRaw, &journal); err != nil {
		t.Fatal(err)
	}
	manifestRaw, err = os.ReadFile(filepath.Join(release, "release-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	journal["manifest_sha256"] = digestSHA256(manifestRaw)
	journal["staged_config_sha256"] = digestSHA256(configRaw)
	writeForwardJSON(t, prior.Journal, journal)
	journalRaw, err = os.ReadFile(prior.Journal)
	if err != nil {
		t.Fatal(err)
	}
	f.prior.SHA256 = digestSHA256(journalRaw)
	if err := os.Mkdir(filepath.Join(prior.Directory, "architectures"), 0700); err != nil {
		t.Fatal(err)
	}
	writeForwardJSON(t, filepath.Join(prior.Directory, "architectures", "bridge.json"), map[string]any{"architecture": "amd64"})
	nodes := []map[string]any{}
	for i, id := range ids {
		address := "192.0.2.2"
		if i == 1 {
			address = "192.0.2.3"
		}
		nodes = append(nodes, map[string]any{"id": id, "address": address, "pins": "fixture-pins"})
		alias := "exit_" + strings.ReplaceAll(id, "-", "")
		writeForwardJSON(t, filepath.Join(prior.Directory, "architectures", alias+".json"), map[string]any{"architecture": "amd64"})
		if err := os.WriteFile(filepath.Join(prior.Directory, alias+".pins"), []byte("fixture-pins"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(prior.Directory, "identity"), []byte("fixture-identity"), 0600); err != nil {
		t.Fatal(err)
	}
	bridgeInv := cloneForwardMap(t, old.Inventory)
	bridgeInv["all"].(map[string]any)["children"].(map[string]any)["exits"] = map[string]any{"hosts": map[string]any{}}
	writeChainStage(
		t,
		filepath.Join(prior.Directory, "inspect"),
		"inspect-upgrade",
		bridgeInv,
		map[string]any{"ultra_lock_directory": root},
		map[string]any{"observed_at": 1, "architecture": "amd64", "identity": "fixture-identity", "nodes": nodes},
		nil,
	)
	writeChainStage(
		t,
		filepath.Join(prior.Directory, "hosts"),
		"inspect-release-hosts",
		old.Inventory,
		map[string]any{"ultra_lock_directory": root, "ultra_release_inspection_directory": filepath.Join(prior.Directory, "architectures")},
		map[string]any{"verified": true},
		nil,
	)
	writeForwardJSON(t, filepath.Join(prior.Directory, "inventory.frozen.json"), old.Inventory)
	diagnostic := deployansible.Diagnostic{
		Stage: "Bind public evidence without exporting environment or credentials",
		Node:  "bridge",
		Code:  "task_failed",
	}
	writeChainStage(
		t,
		filepath.Join(prior.Directory, "domain-inspect"),
		"inspect-upgrade-domains",
		old.Inventory,
		forwardDomainVariables(plan, root, prior.Directory),
		nil,
		&diagnostic,
	)
	writeChainStage(
		t,
		filepath.Join(prior.Directory, "forward-maintenance-1"),
		"contain-upgrade",
		old.Inventory,
		map[string]any{"ultra_lock_directory": root, "ultra_lifecycle_id": lifecycleID(prior.Directory)},
		map[string]any{"verified": true, "maintenance_id": lifecycleID(prior.Directory)},
		nil,
	)
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	writeForwardJSON(t, filepath.Join(root, "lifecycle.json"), map[string]any{"id": lifecycleID(prior.Directory), "phase": "applying"})
	writeForwardJSON(
		t,
		filepath.Join(root, "lifecycle-retired.json"),
		map[string]any{
			"version": 1,
			"ids":     []string{old.ID},
			"handoff": map[string]any{"old_id": old.ID, "new_id": lifecycleID(prior.Directory)},
		},
	)
	f.ledger, err = os.ReadFile(filepath.Join(root, "lifecycle-retired.json"))
	if err != nil {
		t.Fatal(err)
	}
	f.deps = forwardHandoffDeps{
		archive: filepath.Join(release, "ultra-ansible.tar.gz"),
		attach: func(ctx context.Context, lock, id string) (context.Context, func(), error) {
			if f.held || lock != root {
				t.Fatal("invalid lease")
			}
			f.held = true
			f.events = append(f.events, "attach:"+id)
			return ctx, func() { f.held = false; f.events = append(f.events, "release") }, nil
		},
		run: func(ctx context.Context, op string, inv, vars map[string]any, stage, python, executable string) (deployansible.Receipt, error) {
			if !f.held || !sameForwardJSON(inv, old.Inventory) || vars["ultra_forward_old_id"] != lifecycleID(prior.Directory) {
				t.Fatal("census lost original fleet or A lease")
			}
			f.events = append(f.events, "census")
			result := map[string]any{"verified": true, "old_id": lifecycleID(prior.Directory), "new_id": lifecycleID(directory)}
			writeChainStage(t, stage, op, inv, vars, result, nil)
			return deployansible.Receipt{State: "succeeded", Result: deployansible.Result{Values: result}}, nil
		},
		supersede: func(ctx context.Context, a, b string) error {
			if !f.held || a != lifecycleID(prior.Directory) || b != lifecycleID(directory) {
				t.Fatal("invalid supersede")
			}
			raw, err := readForwardEvidence(filepath.Join(directory, "forward-chain.json"))
			var chain forwardChainIntent
			if err != nil || decodeForwardChain(raw, &chain) != nil || chain.OriginalRetirementJSON != string(f.ledger) {
				t.Fatal("original ledger not durable", err)
			}
			if err := verifyForwardIntent(proof, forwardOldOperation{prior.Directory, a, old.Inventory}, root, directory); err != nil {
				t.Fatal("intent not durable", err)
			}
			f.events = append(f.events, "supersede")
			writeForwardJSON(
				t,
				filepath.Join(root, "lifecycle-retired.json"),
				map[string]any{"version": 1, "ids": []string{old.ID, a}, "handoff": map[string]any{"old_id": a, "new_id": b}},
			)
			writeForwardJSON(t, filepath.Join(root, "lifecycle.json"), map[string]any{"id": b, "phase": "applying"})
			return nil
		},
	}
	return f
}
func (f *chainFixture) run() (context.Context, func(), error) {
	ctx := context.WithValue(context.Background(), forwardPriorCandidateKey{}, f.prior)
	return forwardUpgradeHandoff(ctx, f.proof, f.old, f.root, f.directory, "/python", "/ansible", f.deps)
}
func TestForwardChainContainedContinuationUnavailableBeforeMutation(t *testing.T) {
	for _, evidence := range []string{"legacy", "additional-baseline", "repeated-attempt"} {
		t.Run(evidence, func(t *testing.T) {
			f := forwardChainFixture(t)
			if evidence == "additional-baseline" {
				// Merely adding state fields to an authenticated inspection cannot
				// enable a stopped-service protocol that has not been implemented.
				stage := filepath.Join(f.prior.Directory, "inspect")
				raw, err := os.ReadFile(filepath.Join(stage, "result.json"))
				if err != nil {
					t.Fatal(err)
				}
				var result map[string]any
				if err := json.Unmarshal(raw, &result); err != nil {
					t.Fatal(err)
				}
				result["contained_baseline"] = map[string]any{
					"version":        1,
					"relay_active":   true,
					"bot_active":     true,
					"certbot_active": true,
				}
				inv, vars, err := forwardSavedRequest(stage)
				if err != nil {
					t.Fatal(err)
				}
				writeChainStage(t, stage, "inspect-upgrade", inv, vars, result, nil)
			}
			attempts := 1
			if evidence == "repeated-attempt" {
				attempts = 2
			}
			for attempt := 0; attempt < attempts; attempt++ {
				_, release, err := f.run()
				if err == nil || err.Error() != "upgrade_forward_contained_continuation_unavailable" || release != nil {
					t.Fatalf("unexpected contained recovery result: release=%v err=%v", release != nil, err)
				}
				if len(f.events) != 0 || f.held {
					t.Fatal("touched lifecycle or ran census", f.events)
				}
				for _, name := range []string{"forward-chain.json", "forward-handoff.json", "inspect", "runtime-prepare", "activate"} {
					if _, err := os.Lstat(filepath.Join(f.directory, name)); !os.IsNotExist(err) {
						t.Fatalf("created %s: %v", name, err)
					}
				}
				raw, err := os.ReadFile(filepath.Join(f.root, "lifecycle-retired.json"))
				if err != nil || string(raw) != string(f.ledger) {
					t.Fatal("changed retirement ledger", err)
				}
				if err := verifyForwardApplying(f.root, lifecycleID(f.prior.Directory)); err != nil {
					t.Fatal("lost A applying authority", err)
				}
			}
		})
	}
}

func TestForwardChainRejectsUnsafePriorEvidence(t *testing.T) {
	for _, kind := range []string{"activate", "runtime-inspect", "domain-prepare", "baseline.input.json", "unknown", "failed-containment", "failed-drain", "domain-result", "foreign-lifecycle", "released", "prior-retired", "new-retired", "wrong-handoff", "changed-request", "changed-source", "missing-containment", "changed-proof", "foreign-journal", "unknown-stage-file", "missing-timestamps"} {
		t.Run(kind, func(t *testing.T) {
			f := forwardChainFixture(t)
			switch kind {
			case "activate", "runtime-inspect", "domain-prepare":
				if err := os.Mkdir(filepath.Join(f.prior.Directory, kind), 0700); err != nil {
					t.Fatal(err)
				}
			case "baseline.input.json", "unknown":
				if err := os.WriteFile(filepath.Join(f.prior.Directory, kind), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "failed-containment":
				writeForwardJSON(
					t,
					filepath.Join(f.prior.Directory, "forward-maintenance-1", "receipt.json"),
					map[string]any{"state": "failed"},
				)
			case "failed-drain":
				intent, err := loadForwardIntent(filepath.Join(f.prior.Directory, "forward-handoff.json"))
				if err != nil {
					t.Fatal(err)
				}
				writeForwardJSON(t, filepath.Join(intent.Stage, "receipt.json"), map[string]any{"state": "failed"})
			case "domain-result":
				writeForwardJSON(t, filepath.Join(f.prior.Directory, "domain-inspect", "result.json"), map[string]any{"verified": true})
			case "foreign-lifecycle":
				writeForwardJSON(
					t,
					filepath.Join(f.root, "lifecycle.json"),
					map[string]any{"id": lifecycleID("foreign"), "phase": "applying"},
				)
			case "released":
				writeForwardJSON(
					t,
					filepath.Join(f.root, "lifecycle.json"),
					map[string]any{"id": lifecycleID(f.prior.Directory), "phase": "released"},
				)
			case "prior-retired", "new-retired", "wrong-handoff":
				ids := []string{f.old.ID}
				a, b := f.old.ID, lifecycleID(f.prior.Directory)
				if kind == "prior-retired" {
					ids = append(ids, b)
				}
				if kind == "new-retired" {
					ids = append(ids, lifecycleID(f.directory))
				}
				if kind == "wrong-handoff" {
					a = lifecycleID("foreign")
				}
				writeForwardJSON(
					t,
					filepath.Join(f.root, "lifecycle-retired.json"),
					map[string]any{"version": 1, "ids": ids, "handoff": map[string]any{"old_id": a, "new_id": b}},
				)
			case "changed-request":
				writeForwardJSON(t, filepath.Join(f.prior.Directory, "domain-inspect", "request.json"), map[string]any{})
			case "changed-source":
				if err := os.WriteFile(filepath.Join(f.prior.Directory, "hosts", "bundle", "controller.py"), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-containment":
				if err := os.RemoveAll(filepath.Join(f.prior.Directory, "forward-maintenance-1")); err != nil {
					t.Fatal(err)
				}
			case "changed-proof":
				f.proof.SHA256 = strings.Repeat("f", 64)
			case "foreign-journal":
				f.prior.SHA256 = strings.Repeat("f", 64)
			case "unknown-stage-file":
				if err := os.WriteFile(filepath.Join(f.prior.Directory, "hosts", "unknown"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-timestamps":
				raw, err := os.ReadFile(filepath.Join(f.prior.Directory, "hosts", "receipt.json"))
				if err != nil {
					t.Fatal(err)
				}
				var r map[string]any
				if err := json.Unmarshal(raw, &r); err != nil {
					t.Fatal(err)
				}
				delete(r, "finished_at")
				writeForwardJSON(t, filepath.Join(f.prior.Directory, "hosts", "receipt.json"), r)
			}
			if _, _, err := f.run(); err == nil {
				t.Fatal("accepted unsafe prior")
			}
			if len(f.events) != 0 {
				t.Fatal("touched lifecycle before validation", f.events)
			}
		})
	}
}
