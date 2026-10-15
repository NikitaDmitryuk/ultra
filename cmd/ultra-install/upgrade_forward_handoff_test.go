package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func forwardFixture(t *testing.T) (forwardUpgradeJournal, string, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	commit := strings.Repeat("0", 39) + "1"
	attempt := strings.Repeat("a", 64)
	version := "v0.0.1"
	directory := filepath.Join(root, "upgrade-"+version)
	input := filepath.Join(root, "operator-inputs", "manual-"+commit+"-"+attempt)
	for _, path := range []string{filepath.Join(directory, "activate"), input} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	config := []byte(fmt.Sprintf("INSTALL_SCHEMA_VERSION=2\nBRIDGE_IP=192.0.2.1\nMAIN_EXIT_IP=192.0.2.2\nBOT_DOMAIN=sync.example.com\nVPN_DOMAIN=edge.example.com\nACME_EMAIL=owner@example.com\nPUBLIC_XHTTP_PATH=/connect\nREUSE_BRIDGE_SPEC=true\nULTRA_AUTOMATION_VERSION=%s\nULTRA_AUTOMATION_RELEASE_DIR=%s\nULTRA_AUTOMATION_AGE_RECIPIENT=age1fixture\nULTRA_AUTOMATION_BRIDGE_PROVIDER=fixture\nULTRA_AUTOMATION_KNOWN_HOSTS_FILE=/pins\nULTRA_AUTOMATION_STATIC_NODES=[{\"name\":\"NL\",\"address\":\"192.0.2.2\",\"provider\":\"fixture\"}]\nULTRA_AUTOMATION_ADMIN_TELEGRAM_ID=123\n", version, filepath.Join(input, "release")))
	write := func(path string, raw []byte) {
		t.Helper()
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(input, "install.config"), config)
	plan, err := installplan.LoadConfig(filepath.Join(input, "install.config"))
	if err != nil {
		t.Fatal(err)
	}
	if err = installplan.ValidatePlan(plan); err != nil {
		t.Fatal(err)
	}
	if err = freezeOperatorPlan(directory, plan, filepath.Join(input, "release")); err != nil {
		t.Fatal(err)
	}
	inventory := map[string]any{"all": map[string]any{"children": map[string]any{"bridge": map[string]any{"hosts": map[string]any{"bridge": map[string]any{"ansible_host": "192.0.2.1"}}}, "exits": map[string]any{"hosts": map[string]any{"exit_a": map[string]any{"ansible_host": "192.0.2.2"}, "exit_b": map[string]any{"ansible_host": "192.0.2.3"}}}}}}
	manifestSHA := strings.Repeat("b", 64)
	request, _ := json.Marshal(map[string]any{"inventory": inventory, "variables": map[string]any{"ultra_lifecycle_id": lifecycleID(directory), "ultra_release_manifest_sha256": manifestSHA, "ultra_release_manifest": map[string]any{"source_commit": commit, "version": version}}})
	write(filepath.Join(directory, "activate", "request.json"), request)
	job, _ := json.Marshal(map[string]any{"schema_version": 1, "operation": "upgrade", "request_sha256": digestSHA256(request)})
	for _, name := range []string{"job.json", "receipt.json"} {
		write(filepath.Join(directory, "activate", name), job)
	}
	journal, _ := json.Marshal(map[string]any{"schema": 1, "commit": commit, "version": version, "remote_attempt": attempt, "stage": "upgrade", "mutator_dispatched": true, "manifest_sha256": manifestSHA, "staged_config_sha256": digestSHA256(config)})
	path := filepath.Join(root, "archived-manual.json")
	write(path, journal)
	return forwardUpgradeJournal{path, digestSHA256(journal)}, root, directory
}

func TestForwardOldOperationUsesBoundFrozenFleet(t *testing.T) {
	proof, root, directory := forwardFixture(t)
	old, err := discoverForwardOldOperation(proof, root)
	if err != nil || old.Directory != directory || old.ID != lifecycleID(directory) {
		t.Fatalf("bound discovery: %+v %v", old, err)
	}
	exits := old.Inventory["all"].(map[string]any)["children"].(map[string]any)["exits"].(map[string]any)["hosts"].(map[string]any)
	if len(exits) != 2 {
		t.Fatal("lost frozen hosts")
	}
}

func TestForwardOldOperationRejectsAmbiguousEvidence(t *testing.T) {
	for _, kind := range []string{"digest", "version", "commit", "dispatch", "stage", "config", "plan", "request", "job", "receipt", "symlink", "public"} {
		t.Run(kind, func(t *testing.T) {
			proof, root, directory := forwardFixture(t)
			switch kind {
			case "digest":
				proof.SHA256 = strings.Repeat("c", 64)
			case "config", "plan", "request", "job", "receipt":
				path := filepath.Join(directory, "activate", kind+".json")
				if kind == "plan" {
					path = filepath.Join(directory, "operator-plan.json")
				}
				if kind == "config" {
					matches, _ := filepath.Glob(filepath.Join(root, "operator-inputs", "*", "install.config"))
					path = matches[0]
				}
				if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				path := proof.Path + ".link"
				if err := os.Symlink(proof.Path, path); err != nil {
					t.Fatal(err)
				}
				proof.Path = path
			case "public":
				if err := os.Chmod(proof.Path, 0644); err != nil {
					t.Fatal(err)
				}
			default:
				raw, _ := os.ReadFile(proof.Path)
				var journal map[string]any
				_ = json.Unmarshal(raw, &journal)
				switch kind {
				case "version":
					journal["version"] = "v0.0.2"
				case "commit":
					journal["commit"] = strings.Repeat("f", 40)
				case "dispatch":
					journal["mutator_dispatched"] = false
				case "stage":
					journal["stage"] = "prepared"
				}
				raw, _ = json.Marshal(journal)
				if err := os.WriteFile(proof.Path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				proof.SHA256 = digestSHA256(raw)
			}
			if _, err := discoverForwardOldOperation(proof, root); err == nil {
				t.Fatal("accepted ambiguous old operation")
			}
		})
	}
}

func writeForwardJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func forwardReplayFixture(t *testing.T) (forwardUpgradeJournal, forwardOldOperation, string, string, forwardHandoffDeps, *[]string, *bool) {
	t.Helper()
	proof, root, _ := forwardFixture(t)
	old, err := discoverForwardOldOperation(proof, root)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "upgrade-v0.0.2")
	if err = os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	writeForwardJSON(t, filepath.Join(root, "lifecycle.json"), map[string]any{"id": old.ID, "phase": "applying"})
	events := []string{}
	held := false
	deps := forwardHandoffDeps{
		attach: func(ctx context.Context, lock, id string) (context.Context, func(), error) {
			if held {
				t.Fatal("double attachment")
			}
			held = true
			events = append(events, "attach:"+id)
			return ctx, func() { held = false; events = append(events, "release") }, nil
		},
		run: func(ctx context.Context, operation string, inventory, variables map[string]any, stage, python, executable string) (deployansible.Receipt, error) {
			if !held {
				t.Fatal("drain without lease")
			}
			events = append(events, "drain")
			if operation != "drain-upgrade-workers" || filepath.Dir(stage) != directory {
				t.Fatal("wrong fixed drain")
			}
			if err := os.Mkdir(stage, 0700); err != nil {
				t.Fatal(err)
			}
			request, _ := json.Marshal(map[string]any{"inventory": inventory, "variables": variables})
			if err := os.WriteFile(filepath.Join(stage, "request.json"), request, 0600); err != nil {
				t.Fatal(err)
			}
			sha := digestSHA256(request)
			job := map[string]any{"schema_version": 1, "operation": operation, "request_sha256": sha, "binary_sha256": sha}
			writeForwardJSON(t, filepath.Join(stage, "job.json"), job)
			output := map[string]any{"verified": true, "old_id": old.ID, "new_id": lifecycleID(directory)}
			writeForwardJSON(t, filepath.Join(stage, "result.json"), output)
			job["state"] = "succeeded"
			job["result"] = output
			writeForwardJSON(t, filepath.Join(stage, "receipt.json"), job)
			return deployansible.Receipt{State: "succeeded", RequestSHA256: sha, BinarySHA256: sha, Result: deployansible.Result{Values: output}}, nil
		},
		supersede: func(ctx context.Context, oldID, newID string) error {
			if !held {
				t.Fatal("supersede without lease")
			}
			if err := verifyForwardIntent(proof, old, root, directory); err != nil {
				t.Fatalf("intent not durable before supersede: %v", err)
			}
			events = append(events, "supersede")
			writeForwardJSON(t, filepath.Join(root, "lifecycle-retired.json"), map[string]any{"version": 1, "ids": []string{oldID}, "handoff": map[string]any{"old_id": oldID, "new_id": newID}})
			writeForwardJSON(t, filepath.Join(root, "lifecycle.json"), map[string]any{"id": newID, "phase": "applying"})
			return nil
		},
	}
	return proof, old, root, directory, deps, &events, &held
}

func TestForwardHandoffLostSupersedeResponseReplaysNewLease(t *testing.T) {
	proof, old, root, directory, deps, events, held := forwardReplayFixture(t)
	commit := deps.supersede
	deps.supersede = func(ctx context.Context, a, b string) error {
		if err := commit(ctx, a, b); err != nil {
			return err
		}
		return errors.New("lost response")
	}
	if _, _, err := forwardUpgradeHandoff(context.Background(), proof, old, root, directory, "/python", "/ansible", deps); err == nil {
		t.Fatal("lost response accepted")
	}
	if *held {
		t.Fatal("failed call leaked lease")
	}
	first := append([]string(nil), (*events)...)
	if strings.Join(first, ",") != "attach:"+old.ID+",drain,supersede,release" {
		t.Fatal(first)
	}
	_, release, err := forwardUpgradeHandoff(context.Background(), proof, old, root, directory, "/python", "/ansible", deps)
	if err != nil {
		t.Fatal(err)
	}
	if !*held || len(*events) != len(first)+1 || (*events)[len(first)] != "attach:"+lifecycleID(directory) {
		t.Fatal("replay reran old dispatch", *events)
	}
	release()
	info, err := os.Stat(filepath.Join(directory, "forward-handoff.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("intent not private", err)
	}
}

func TestForwardHandoffOldOwnerAlwaysRepeatsFreshCensus(t *testing.T) {
	proof, old, root, directory, deps, events, _ := forwardReplayFixture(t)
	commit := deps.supersede
	deps.supersede = func(context.Context, string, string) error { return errors.New("not committed") }
	if _, _, err := forwardUpgradeHandoff(context.Background(), proof, old, root, directory, "/python", "/ansible", deps); err == nil {
		t.Fatal("failed handoff accepted")
	}
	first, err := loadForwardIntent(filepath.Join(directory, "forward-handoff.json"))
	if err != nil {
		t.Fatal(err)
	}
	deps.supersede = commit
	_, release, err := forwardUpgradeHandoff(context.Background(), proof, old, root, directory, "/python", "/ansible", deps)
	if err != nil {
		t.Fatal(err)
	}
	release()
	second, err := loadForwardIntent(filepath.Join(directory, "forward-handoff.json"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Stage == second.Stage || strings.Count(strings.Join(*events, ","), "drain") != 2 {
		t.Fatal("cached old census reused", *events)
	}
}

func TestForwardHandoffReplayRejectsChangedEvidence(t *testing.T) {
	for _, kind := range []string{"missing-intent", "proof", "old-id", "new-id", "stage", "request", "job", "receipt", "result", "ledger", "new-retired", "unknown-ledger-field", "released", "foreign", "symlink", "public", "directory-mode"} {
		t.Run(kind, func(t *testing.T) {
			proof, old, root, directory, deps, events, _ := forwardReplayFixture(t)
			_, release, err := forwardUpgradeHandoff(context.Background(), proof, old, root, directory, "/python", "/ansible", deps)
			if err != nil {
				t.Fatal(err)
			}
			release()
			path := filepath.Join(directory, "forward-handoff.json")
			intent, err := loadForwardIntent(path)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "missing-intent":
				err = os.Remove(path)
			case "proof":
				proof.SHA256 = strings.Repeat("f", 64)
			case "old-id":
				intent.OldID = lifecycleID("foreign")
				writeForwardJSON(t, path, intent)
			case "new-id":
				intent.NewID = lifecycleID("foreign")
				writeForwardJSON(t, path, intent)
			case "stage":
				intent.Stage = filepath.Join(root, "elsewhere")
				writeForwardJSON(t, path, intent)
			case "request", "job", "receipt", "result":
				err = os.WriteFile(filepath.Join(intent.Stage, kind+".json"), []byte("{}"), 0600)
			case "ledger":
				err = os.WriteFile(filepath.Join(root, "lifecycle-retired.json"), []byte("{}"), 0600)
			case "new-retired":
				writeForwardJSON(t, filepath.Join(root, "lifecycle-retired.json"), map[string]any{"version": 1, "ids": []string{old.ID, lifecycleID(directory)}, "handoff": map[string]any{"old_id": old.ID, "new_id": lifecycleID(directory)}})
			case "unknown-ledger-field":
				writeForwardJSON(t, filepath.Join(root, "lifecycle-retired.json"), map[string]any{"version": 1, "ids": []string{old.ID}, "handoff": map[string]any{"old_id": old.ID, "new_id": lifecycleID(directory)}, "unknown": true})
			case "released":
				writeForwardJSON(t, filepath.Join(root, "lifecycle.json"), map[string]any{"id": lifecycleID(directory), "phase": "released"})
			case "foreign":
				writeForwardJSON(t, filepath.Join(root, "lifecycle.json"), map[string]any{"id": lifecycleID("foreign"), "phase": "applying"})
			case "symlink":
				err = os.Rename(path, path+".real")
				if err == nil {
					err = os.Symlink(path+".real", path)
				}
			case "public":
				err = os.Chmod(path, 0644)
			case "directory-mode":
				err = os.Chmod(intent.Stage, 0755)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := len(*events)
			if _, _, err = forwardUpgradeHandoff(context.Background(), proof, old, root, directory, "/python", "/ansible", deps); err == nil {
				t.Fatal("accepted changed replay evidence")
			}
			if len(*events) != before {
				t.Fatal("ambiguous evidence touched lifecycle", *events)
			}
		})
	}
}

func TestForwardHandoffFailedDrainCannotPersistOrSupersede(t *testing.T) {
	proof, old, root, directory, deps, events, held := forwardReplayFixture(t)
	deps.run = func(context.Context, string, map[string]any, map[string]any, string, string, string) (deployansible.Receipt, error) {
		return deployansible.Receipt{}, errors.New("workers live")
	}
	if _, _, err := forwardUpgradeHandoff(context.Background(), proof, old, root, directory, "/python", "/ansible", deps); err == nil {
		t.Fatal("failed drain accepted")
	}
	if *held {
		t.Fatal("lease leaked")
	}
	if _, err := os.Lstat(filepath.Join(directory, "forward-handoff.json")); !os.IsNotExist(err) {
		t.Fatal("failed drain persisted intent", err)
	}
	if strings.Contains(strings.Join(*events, ","), "supersede") {
		t.Fatal("failed drain superseded")
	}
}
