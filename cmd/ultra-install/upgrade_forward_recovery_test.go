package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestForwardRecoveryBrokerOrderingAndFailure(t *testing.T) {
	for _, kind := range []string{"success", "restart-failure", "lifecycle-changed", "retired", "activation-started"} {
		t.Run(kind, func(t *testing.T) {
			proof, old, root, directory, deps, events, held := forwardReplayFixture(t)
			deps.prepare = func(context.Context) error {
				if !*held {
					t.Fatal("bootstrap without held old lease")
				}
				*events = append(*events, "bootstrap-resume")
				if kind == "restart-failure" {
					return errors.New("restart failed")
				}
				if kind == "lifecycle-changed" {
					writeForwardJSON(t, filepath.Join(root, "lifecycle.json"), map[string]any{"id": lifecycleID(directory), "phase": "applying"})
				}
				return nil
			}
			if kind == "retired" {
				writeForwardJSON(t, filepath.Join(root, "lifecycle-retired.json"), map[string]any{"version": 1, "ids": []string{old.ID}})
			}
			if kind == "activation-started" {
				if err := os.Mkdir(filepath.Join(directory, "activate"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			_, release, err := forwardUpgradeHandoff(context.Background(), proof, old, root, directory, "/python", "/ansible", deps)
			if kind == "success" {
				if err != nil {
					t.Fatal(err)
				}
				release()
				if got := strings.Join(*events, ","); got != "attach:"+old.ID+",bootstrap-resume,drain,supersede,release" {
					t.Fatal(got)
				}
			} else {
				if err == nil || *held {
					t.Fatal("unsafe failure", err, *held)
				}
				if strings.Contains(strings.Join(*events, ","), "drain") {
					t.Fatal("drained after unverified bootstrap")
				}
				if kind == "restart-failure" && verifyForwardApplying(root, old.ID) != nil {
					t.Fatal("restart failure released durable reservation")
				}
			}
		})
	}
}

func forwardPriorRecoveryFixture(t *testing.T) (forwardUpgradeJournal, forwardOldOperation, string, string, forwardPriorCandidate) {
	t.Helper()
	proof, old, root, priorDir, deps, _, _ := forwardReplayFixture(t)
	deps.supersede = func(context.Context, string, string) error { return errors.New("old broker rejects next_id") }
	if _, _, err := forwardUpgradeHandoff(context.Background(), proof, old, root, priorDir, "/python", "/ansible", deps); err == nil {
		t.Fatal("fixture superseded")
	}
	commit := strings.Repeat("0", 39) + "2"
	attempt := strings.Repeat("c", 64)
	version := "v0.0.2"
	input := filepath.Join(root, "operator-inputs", "manual-"+commit+"-"+attempt)
	release := filepath.Join(input, "release")
	if err := os.MkdirAll(release, 0700); err != nil {
		t.Fatal(err)
	}
	oldInputs, _ := filepath.Glob(filepath.Join(root, "operator-inputs", "*", "install.config"))
	raw, err := os.ReadFile(oldInputs[0])
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.ReplaceAll(strings.ReplaceAll(string(raw), "v0.0.1", version), filepath.Dir(oldInputs[0]), input))
	if err := os.WriteFile(filepath.Join(input, "install.config"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	plan, err := installplan.LoadConfig(filepath.Join(input, "install.config"))
	if err != nil {
		t.Fatal(err)
	}
	if err := installplan.ValidatePlan(plan); err != nil {
		t.Fatal(err)
	}
	if err := freezeOperatorPlan(priorDir, plan, release); err != nil {
		t.Fatal(err)
	}
	writeForwardJSON(t, filepath.Join(priorDir, "execution-mode.json"), frozenExecution{Schema: 1, Local: true, Target: plan.Bridge.SSHHost + "|" + plan.Bridge.Address, LockDirectory: root, OperatorDirectory: filepath.Join(root, "operator")})
	// Exact prior bundle archived in its immutable release, independent of new code.
	intent, err := loadForwardIntent(filepath.Join(priorDir, "forward-handoff.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(intent.Stage, "bundle"), 0700); err != nil {
		t.Fatal(err)
	}
	content := []byte("prior-controller-source")
	if err := os.WriteFile(filepath.Join(intent.Stage, "bundle", "controller.py"), content, 0600); err != nil {
		t.Fatal(err)
	}
	archive, err := os.OpenFile(filepath.Join(release, "ultra-ansible.tar.gz"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(archive)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "controller.py", Mode: 0600, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
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
	names := []string{"ultra-relay-linux-amd64", "ultra-relay-linux-arm64", "ultra-bot-linux-amd64", "ultra-bot-linux-arm64", "ultra-client-linux-amd64", "ultra-client-linux-arm64", "ultra-recovery.tar.gz", "ultra-install-linux-amd64", "ultra-install-linux-arm64", "ultra-ansible.tar.gz", "ultra-ansible-runtime-linux-amd64.tar.gz", "ultra-ansible-runtime-linux-arm64.tar.gz", "mobile-bootstrap.sh", "checksums.txt"}
	assets := []map[string]any{}
	for _, name := range names {
		data := []byte("fixture:" + name)
		if name == "ultra-ansible.tar.gz" {
			data, err = os.ReadFile(filepath.Join(release, name))
			if err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(filepath.Join(release, name), data, 0600); err != nil {
			t.Fatal(err)
		}
		assets = append(assets, map[string]any{"name": name, "sha256": digestSHA256(data), "size": len(data)})
	}
	manifest := map[string]any{"schema_version": 1, "version": version, "source_commit": commit, "database_schema_min": 24, "database_schema_max": 25, "capabilities": []string{"service-access-v1", "provider-pool-quota-v1", "lifecycle-gate-v1", "ansible-deploy-v1"}, "assets": assets}
	writeForwardJSON(t, filepath.Join(release, "release-manifest.json"), manifest)
	manifestRaw, _ := json.Marshal(manifest)
	journal := map[string]any{"schema": 1, "commit": commit, "version": version, "remote_attempt": attempt, "stage": "upgrade", "mutator_dispatched": true, "forward_only": true, "forward_journal_sha256": proof.SHA256, "manifest_sha256": digestSHA256(manifestRaw), "staged_config_sha256": digestSHA256(raw)}
	journalRaw, _ := json.Marshal(journal)
	journalPath := filepath.Join(filepath.Dir(proof.Path), "forward-prior-operation.json")
	if err := os.WriteFile(journalPath, journalRaw, 0600); err != nil {
		t.Fatal(err)
	}
	return proof, old, root, filepath.Join(root, "upgrade-v0.0.3"), forwardPriorCandidate{priorDir, journalPath, digestSHA256(journalRaw)}
}

func TestForwardRecoveryPriorCandidateAudit(t *testing.T) {
	for _, kind := range []string{"success", "foreign-directory", "foreign-proof", "corrupt-intent", "extra-root-file", "extra-drain-file", "extra-bundle-file", "changed-release", "activation", "retired", "runtime-pin", "foreign-runtime-pin", "current-lifecycle-mismatch"} {
		t.Run(kind, func(t *testing.T) {
			proof, old, root, directory, prior := forwardPriorRecoveryFixture(t)
			intent, err := loadForwardIntent(filepath.Join(prior.Directory, "forward-handoff.json"))
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "runtime-pin", "foreign-runtime-pin":
				files, _ := filepath.Glob(filepath.Join(root, "operator-inputs", "*", "release", "release-manifest.json"))
				var manifest automationRelease
				raw, err := os.ReadFile(files[0])
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(raw, &manifest); err != nil {
					t.Fatal(err)
				}
				asset, err := upgradeAsset(&manifest, "ultra-ansible-runtime-linux-"+runtime.GOARCH+".tar.gz")
				if err != nil {
					t.Fatal(err)
				}
				runtimeDir := filepath.Join(root, "runtime-"+asset.SHA)
				if kind == "foreign-runtime-pin" {
					runtimeDir = "/tmp/foreign"
				}
				writeForwardJSON(t, filepath.Join(prior.Directory, "runtime-use.json"), map[string]any{"runtime_directory": runtimeDir})
			case "current-lifecycle-mismatch":
				writeForwardJSON(t, filepath.Join(root, "lifecycle.json"), map[string]any{"id": lifecycleID(directory), "phase": "applying"})
			case "foreign-directory":
				prior.Directory = filepath.Join(root, "upgrade-v0.0.99")
			case "foreign-proof":
				proof.SHA256 = strings.Repeat("d", 64)
			case "corrupt-intent":
				writeForwardJSON(t, filepath.Join(prior.Directory, "forward-handoff.json"), map[string]any{"schema": 1})
			case "extra-root-file", "activation":
				name := "unknown"
				if kind == "activation" {
					name = "activate"
				}
				if err := os.WriteFile(filepath.Join(prior.Directory, name), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "extra-drain-file":
				if err := os.WriteFile(filepath.Join(intent.Stage, "unknown"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "extra-bundle-file":
				if err := os.WriteFile(filepath.Join(intent.Stage, "bundle", "unknown"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "changed-release":
				inputs, _ := filepath.Glob(filepath.Join(root, "operator-inputs", "*", "release", "ultra-install-linux-amd64"))
				if err := os.WriteFile(inputs[0], []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "retired":
				writeForwardJSON(t, filepath.Join(root, "lifecycle-retired.json"), map[string]any{"version": 1, "ids": []string{old.ID}})
			}
			err = verifyForwardPriorCandidate(proof, old, root, directory, prior)
			if (kind == "success" || kind == "runtime-pin") != (err == nil) {
				t.Fatalf("%s: %v", kind, err)
			}
		})
	}
}

func TestForwardRecoveryBootstrapStagesRemainBoundOnRetry(t *testing.T) {
	for _, kind := range []string{"running", "failed", "succeeded", "changed-request", "foreign-job", "missing-receipt", "extra-file"} {
		t.Run(kind, func(t *testing.T) {
			_, old, root, _, prior := forwardPriorRecoveryFixture(t)
			intent, err := loadForwardIntent(filepath.Join(prior.Directory, "forward-handoff.json"))
			if err != nil {
				t.Fatal(err)
			}
			stage := filepath.Join(prior.Directory, "broker-bootstrap-fixture")
			if err := os.Rename(intent.Stage, stage); err != nil {
				t.Fatal(err)
			}
			inputs, _ := filepath.Glob(filepath.Join(root, "operator-inputs", "*", "release", "ultra-ansible.tar.gz"))
			if len(inputs) != 1 {
				t.Fatal(inputs)
			}
			variables := map[string]any{"old": old.ID, "candidate": lifecycleID(prior.Directory)}
			request, _ := json.Marshal(map[string]any{"inventory": old.Inventory, "variables": variables})
			if err := os.WriteFile(filepath.Join(stage, "request.json"), request, 0600); err != nil {
				t.Fatal(err)
			}
			evidence := map[string]any{"schema_version": 1, "operation": "bootstrap-forward-broker", "request_sha256": digestSHA256(request), "binary_sha256": digestSHA256(request)}
			writeForwardJSON(t, filepath.Join(stage, "job.json"), evidence)
			state := kind
			if state != "running" && state != "failed" && state != "succeeded" {
				state = "running"
			}
			evidence["state"] = state
			writeForwardJSON(t, filepath.Join(stage, "receipt.json"), evidence)
			switch kind {
			case "changed-request":
				if err := os.WriteFile(filepath.Join(stage, "request.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "foreign-job":
				evidence["operation"] = "prepare-controller"
				writeForwardJSON(t, filepath.Join(stage, "job.json"), evidence)
			case "missing-receipt":
				if err := os.Remove(filepath.Join(stage, "receipt.json")); err != nil {
					t.Fatal(err)
				}
			case "extra-file":
				if err := os.WriteFile(filepath.Join(stage, "unknown"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err = verifyForwardBrokerStages(prior.Directory, inputs[0], old.Inventory, variables)
			success := kind == "running" || kind == "failed" || kind == "succeeded"
			if success != (err == nil) {
				t.Fatalf("%s: %v", kind, err)
			}
		})
	}
}

func TestForwardRecoveryAdoptionWaitsForSocketWithoutReleasingGate(t *testing.T) {
	proof, old, root, _, _, _, _ := forwardReplayFixture(t)
	_ = proof
	calls := 0
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := resumeForwardBroker(ctx, root, old.ID, func(context.Context, string) error {
		calls++
		if calls == 1 {
			return errors.New("socket starting")
		}
		return nil
	}); err != nil || calls != 2 {
		t.Fatal(calls, err)
	}
	writeForwardJSON(t, filepath.Join(root, "lifecycle.json"), map[string]any{"id": old.ID, "phase": "released"})
	if err := resumeForwardBroker(ctx, root, old.ID, func(context.Context, string) error { t.Fatal("adopted released lifecycle"); return nil }); err == nil {
		t.Fatal("released lifecycle accepted")
	}
}

func TestForwardRecoveryPriorWithoutHandoffIsStrictlyPreMutation(t *testing.T) {
	for _, kind := range []string{"success", "intent-only", "drain-only", "activation", "unknown", "changed-config", "changed-proof", "retired", "foreign-lifecycle", "public-directory"} {
		t.Run(kind, func(t *testing.T) {
			proof, old, root, directory, prior := forwardPriorRecoveryFixture(t)
			intentPath := filepath.Join(prior.Directory, "forward-handoff.json")
			intent, err := loadForwardIntent(intentPath)
			if err != nil {
				t.Fatal(err)
			}
			if kind != "drain-only" {
				if err := os.RemoveAll(intent.Stage); err != nil {
					t.Fatal(err)
				}
			}
			if kind != "intent-only" {
				if err := os.Remove(intentPath); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "activation":
				if err := os.Mkdir(filepath.Join(prior.Directory, "activate"), 0700); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				if err := os.WriteFile(filepath.Join(prior.Directory, "unknown"), []byte("fixture"), 0600); err != nil {
					t.Fatal(err)
				}
			case "changed-config":
				files, _ := filepath.Glob(filepath.Join(root, "operator-inputs", "*", "release", "release-manifest.json"))
				if len(files) != 1 {
					t.Fatal(files)
				}
				if err := os.WriteFile(filepath.Join(filepath.Dir(filepath.Dir(files[0])), "install.config"), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "changed-proof":
				proof.SHA256 = strings.Repeat("d", 64)
			case "retired":
				writeForwardJSON(t, filepath.Join(root, "lifecycle-retired.json"), map[string]any{"version": 1, "ids": []string{lifecycleID(prior.Directory)}})
			case "public-directory":
				if err := os.Chmod(prior.Directory, 0755); err != nil {
					t.Fatal(err)
				}
			case "foreign-lifecycle":
				writeForwardJSON(t, filepath.Join(root, "lifecycle.json"), map[string]any{"id": lifecycleID(directory), "phase": "applying"})
			}
			journalBefore, err := os.ReadFile(prior.Journal)
			if err != nil {
				t.Fatal(err)
			}
			err = verifyForwardPriorCandidate(proof, old, root, directory, prior)
			if (kind == "success") != (err == nil) {
				t.Fatalf("%s: %v", kind, err)
			}
			journalAfter, readErr := os.ReadFile(prior.Journal)
			if readErr != nil || string(journalBefore) != string(journalAfter) {
				t.Fatal("prior journal changed", readErr)
			}
			if kind == "success" {
				entries, err := os.ReadDir(prior.Directory)
				if err != nil || len(entries) != 2 {
					t.Fatal("prior frozen operation changed", err)
				}
			}
		})
	}
}

func TestForwardRecoveryWithoutSavedCensusOrdersBeforeAndAfterBootstrap(t *testing.T) {
	for _, kind := range []string{"success", "census-failed", "bootstrap-failed", "adopt-failed"} {
		t.Run(kind, func(t *testing.T) {
			proof, old, root, directory, deps, events, held := forwardReplayFixture(t)
			originalRun := deps.run
			deps.prepare = func(ctx context.Context) error {
				return prepareForwardRecovery(ctx, true,
					func(ctx context.Context) error {
						if !*held {
							t.Fatal("census without old OFD")
						}
						if kind == "census-failed" {
							*events = append(*events, "census-failed")
							return errors.New("workers live")
						}
						_, err := runForwardCensus(ctx, proof, old, root, directory, "/python", "/ansible", originalRun)
						return err
					},
					func(context.Context) error {
						if !*held || verifyForwardApplying(root, old.ID) != nil {
							t.Fatal("bootstrap without predecessor gate")
						}
						if _, err := os.Lstat(filepath.Join(directory, "forward-handoff.json")); !os.IsNotExist(err) {
							t.Fatal("intent published before broker adoption")
						}
						*events = append(*events, "bootstrap")
						if kind == "bootstrap-failed" {
							return errors.New("restart failed")
						}
						return nil
					},
					func(context.Context) error {
						if !*held {
							t.Fatal("adopt without old OFD")
						}
						*events = append(*events, "adopt")
						if kind == "adopt-failed" {
							return errors.New("socket unavailable")
						}
						return nil
					})
			}
			_, release, err := forwardUpgradeHandoff(context.Background(), proof, old, root, directory, "/python", "/ansible", deps)
			if kind == "success" {
				if err != nil {
					t.Fatal(err)
				}
				release()
				expected := "attach:" + old.ID + ",drain,bootstrap,adopt,drain,supersede,release"
				if got := strings.Join(*events, ","); got != expected {
					t.Fatal(got)
				}
			} else {
				if err == nil || *held || verifyForwardApplying(root, old.ID) != nil {
					t.Fatal("unsafe failure", err, *held)
				}
				if _, err := os.Lstat(filepath.Join(directory, "forward-handoff.json")); !os.IsNotExist(err) {
					t.Fatal("failed preparation published intent")
				}
				if strings.Contains(strings.Join(*events, ","), "supersede") {
					t.Fatal("failed preparation retired old lifecycle")
				}
				if kind == "census-failed" && strings.Contains(strings.Join(*events, ","), "bootstrap") {
					t.Fatal("bootstrapped before verified census")
				}
			}
		})
	}
}

func TestForwardRecoveryReplaysSameCandidateAfterPreBootstrapCensus(t *testing.T) {
	proof, old, root, directory, deps, events, held := forwardReplayFixture(t)
	originalRun := deps.run
	failBootstrap := true
	deps.prepare = func(ctx context.Context) error {
		return prepareForwardRecovery(ctx, true,
			func(ctx context.Context) error {
				_, err := runForwardCensus(ctx, proof, old, root, directory, "/python", "/ansible", originalRun)
				return err
			},
			func(context.Context) error {
				*events = append(*events, "bootstrap")
				if failBootstrap {
					return errors.New("interrupted bootstrap")
				}
				return nil
			},
			func(context.Context) error { *events = append(*events, "adopt"); return nil })
	}
	if _, _, err := forwardUpgradeHandoff(context.Background(), proof, old, root, directory, "/python", "/ansible", deps); err == nil || *held {
		t.Fatal("interruption did not fail closed", err)
	}
	if verifyForwardApplying(root, old.ID) != nil {
		t.Fatal("interruption released predecessor reservation")
	}
	if _, err := os.Lstat(filepath.Join(directory, "forward-handoff.json")); !os.IsNotExist(err) {
		t.Fatal("interruption published final intent")
	}
	stages, err := filepath.Glob(filepath.Join(directory, "handoff-drain-*"))
	if err != nil || len(stages) != 1 {
		t.Fatal(stages, err)
	}
	first := stages[0]
	before := map[string]string{}
	for _, name := range []string{"request.json", "job.json", "receipt.json", "result.json"} {
		raw, err := os.ReadFile(filepath.Join(first, name))
		if err != nil {
			t.Fatal(err)
		}
		before[name] = digestSHA256(raw)
	}
	failBootstrap = false
	_, release, err := forwardUpgradeHandoff(context.Background(), proof, old, root, directory, "/python", "/ansible", deps)
	if err != nil {
		t.Fatal(err)
	}
	release()
	stages, err = filepath.Glob(filepath.Join(directory, "handoff-drain-*"))
	if err != nil || len(stages) != 3 {
		t.Fatal("retry did not repeat both censuses", stages, err)
	}
	intent, err := loadForwardIntent(filepath.Join(directory, "forward-handoff.json"))
	if err != nil || intent.Stage == first {
		t.Fatal("retry reused stale census", intent, err)
	}
	for name, digest := range before {
		raw, err := os.ReadFile(filepath.Join(first, name))
		if err != nil || digestSHA256(raw) != digest {
			t.Fatal("retry modified prior census", name, err)
		}
	}
	if err := verifyForwardRetirement(root, old.ID, lifecycleID(directory)); err != nil {
		t.Fatal("retry did not atomically supersede", err)
	}
}
