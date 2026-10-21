package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ansibleassets "github.com/NikitaDmitryuk/ultra/deploy/ansible"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

func retainedRebuildFixture(t *testing.T) retainedPrimaryRebuildInput {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	hosts := map[string]any{}
	for i, scope := range []struct{ group, host string }{{"bridge", "bridge"}, {"exits", "exit_0"}, {"databases", "database"}} {
		hosts[scope.group] = map[string]any{
			"hosts": map[string]any{scope.host: map[string]any{"ansible_host": []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}[i]}},
		}
	}
	hash := strings.Repeat("a", 64)
	return retainedPrimaryRebuildInput{
		Inventory: map[string]any{"all": map[string]any{"children": hosts}},
		Variables: map[string]any{
			"ultra_db_tunnel_private_key_source": "/private/preserved-key",
			"ultra_db_tunnel_private_key_sha256": hash,
		},
		JournalSHA256:              hash,
		ConfigSHA256:               hash,
		ManifestSHA256:             hash,
		CandidateMigrationsSHA256:  digestSHA256([]byte("1,2,3")),
		CandidateMigrationVersions: "1,2,3",
		FenceEvidenceSHA256:        hash,
		Primary: retainedPrimaryIdentity{
			SystemIdentifier:  "123456789",
			Database:          "app",
			DatabaseOID:       16384,
			MigrationsSHA256:  digestSHA256([]byte("1,2,3")),
			MigrationVersions: "1,2,3",
		},
		Directory:  dir,
		Python:     "/usr/bin/python3",
		Executable: "/usr/bin/ansible-playbook",
	}
}

func retainedRebuildSuccessfulDependencies(
	t *testing.T,
	in retainedPrimaryRebuildInput,
	events *[]string,
) retainedPrimaryRebuildDependencies {
	t.Helper()
	return retainedPrimaryRebuildDependencies{
		VerifyFence: func(context.Context, retainedPrimaryRebuildInput) error {
			*events = append(*events, "fence")
			return nil
		},
		ObservePrimary: func(context.Context, retainedPrimaryRebuildInput) (retainedPrimaryIdentity, error) {
			*events = append(*events, "primary")
			return in.Primary, nil
		},
		Run: func(_ context.Context, op string, _ map[string]any, vars map[string]any, dir, python, exe string) (deployansible.Receipt, error) {
			*events = append(*events, "run")
			if op != retainedPrimaryRebuildOperation || dir != filepath.Join(in.Directory, "execute") || python != in.Python ||
				exe != in.Executable {
				t.Fatal("unexpected executor scope")
			}
			if _, err := os.Lstat(filepath.Join(in.Directory, "retained-primary-receipt.json")); !os.IsNotExist(err) {
				t.Fatal("receipt published before execution")
			}
			return deployansible.Receipt{
				State:         "succeeded",
				RequestSHA256: strings.Repeat("b", 64),
				BinarySHA256:  strings.Repeat("c", 64),
				Result: deployansible.Result{
					Values: map[string]any{
						"verified":                  true,
						"retained_primary_verified": true,
						"relay_ready":               true,
						"bot_ready":                 true,
						"main_exit_ready":           true,
						"recovery_binding_sha256":   vars["ultra_retained_recovery_binding_sha256"],
					},
				},
			}, nil
		},
	}
}
func TestRetainedPrimaryRebuildWritesReceiptAfterChecks(t *testing.T) {
	in := retainedRebuildFixture(t)
	events := []string{}
	deps := retainedRebuildSuccessfulDependencies(t, in, &events)
	if err := runRetainedPrimaryRebuild(context.Background(), in, deps); err != nil {
		t.Fatal(err)
	}
	if strings.Join(events, ",") != "fence,primary,run,fence,primary" {
		t.Fatal(events)
	}
	path := filepath.Join(in.Directory, "retained-primary-receipt.json")
	raw, err := readRebuildInput(path, true)
	if err != nil {
		t.Fatal(err)
	}
	var receipt retainedPrimaryRebuildReceipt
	if err = json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	if !receipt.Verified || receipt.Primary != in.Primary || receipt.OriginalJournalSHA256 != in.JournalSHA256 {
		t.Fatal("receipt lost input binding")
	}
	if _, ok := in.Variables["ultra_retained_primary"]; ok {
		t.Fatal("mutated caller variables")
	}
}
func TestRetainedPrimaryRebuildFailsClosed(t *testing.T) {
	for _, scenario := range []string{"missing-fence", "missing-primary", "fence-denied", "initial-identity", "candidate-migrations", "execution-error", "health-failed", "result-binding", "final-fence", "final-identity", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			in := retainedRebuildFixture(t)
			events := []string{}
			deps := retainedRebuildSuccessfulDependencies(t, in, &events)
			ctx := context.Background()
			switch scenario {
			case "missing-fence":
				deps.VerifyFence = nil
			case "missing-primary":
				deps.ObservePrimary = nil
			case "fence-denied":
				deps.VerifyFence = func(context.Context, retainedPrimaryRebuildInput) error { return errors.New("not fenced") }
			case "initial-identity":
				deps.ObservePrimary = func(context.Context, retainedPrimaryRebuildInput) (retainedPrimaryIdentity, error) {
					return retainedPrimaryIdentity{}, nil
				}
			case "candidate-migrations":
				in.CandidateMigrationsSHA256 = strings.Repeat("b", 64)
			case "execution-error":
				deps.Run = func(context.Context, string, map[string]any, map[string]any, string, string, string) (deployansible.Receipt, error) {
					return deployansible.Receipt{}, errors.New("failed")
				}
			case "health-failed", "result-binding":
				original := deps.Run
				deps.Run = func(ctx context.Context, op string, inv, vars map[string]any, dir, py, exe string) (deployansible.Receipt, error) {
					r, e := original(ctx, op, inv, vars, dir, py, exe)
					if scenario == "health-failed" {
						r.Result.Values["bot_ready"] = false
					} else {
						r.Result.Values["recovery_binding_sha256"] = strings.Repeat("d", 64)
					}
					return r, e
				}
			case "final-fence":
				calls := 0
				deps.VerifyFence = func(context.Context, retainedPrimaryRebuildInput) error {
					calls++
					if calls == 2 {
						return errors.New("lost fence")
					}
					return nil
				}
			case "final-identity":
				calls := 0
				deps.ObservePrimary = func(context.Context, retainedPrimaryRebuildInput) (retainedPrimaryIdentity, error) {
					calls++
					if calls == 2 {
						return retainedPrimaryIdentity{}, nil
					}
					return in.Primary, nil
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err := runRetainedPrimaryRebuild(ctx, in, deps); err == nil {
				t.Fatal("accepted unverified recovery")
			}
			if _, err := os.Lstat(filepath.Join(in.Directory, "retained-primary-receipt.json")); !os.IsNotExist(err) {
				t.Fatal("failed recovery wrote receipt")
			}
		})
	}
}
func TestRetainedPrimaryRebuildRejectsDatabaseMutationInputs(t *testing.T) {
	for _, key := range []string{"ultra_postgres", "ultra_database_import_dump", "ultra_database_import_sha256", "ultra_result_file"} {
		t.Run(key, func(t *testing.T) {
			in := retainedRebuildFixture(t)
			in.Variables[key] = "forbidden"
			if err := validateRetainedPrimaryRebuild(in); err == nil {
				t.Fatal("accepted " + key)
			}
		})
	}
	in := retainedRebuildFixture(t)
	children := in.Inventory["all"].(map[string]any)["children"].(map[string]any)
	children["exits"].(map[string]any)["hosts"].(map[string]any)["exit_1"] = map[string]any{"ansible_host": "192.0.2.9"}
	if err := validateRetainedPrimaryRebuild(in); err == nil {
		t.Fatal("accepted extra exit")
	}
}
func TestRetainedPrimaryReceiptDoesNotOverwrite(t *testing.T) {
	dir := retainedRebuildFixture(t).Directory
	if err := publishRetainedPrimaryReceipt(dir, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := publishRetainedPrimaryReceipt(dir, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := publishRetainedPrimaryReceipt(dir, []byte("two")); err == nil {
		t.Fatal("overwrote existing receipt")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "retained-primary-receipt.json"))
	if err != nil || string(raw) != "one" {
		t.Fatal("changed receipt")
	}
}
func TestRetainedPrimaryPlaybookExcludesDatabaseProvisioning(t *testing.T) {
	raw, err := ansibleassets.Bundle.ReadFile("playbooks/rebuild-retained-primary.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, bad := range []string{"bootstrap-postgres.yml", "bootstrap.yml", "role: postgres\n", "name: database_import", "pg_restore", "DROP DATABASE", "CREATE DATABASE", "encode(sha256("} {
		if strings.Contains(text, bad) {
			t.Fatal("forbidden provisioning: " + bad)
		}
	}
	for _, needed := range []string{"BEGIN READ ONLY;", "default_transaction_read_only=on", "ultra_retained_candidate_migration_versions", "migration_versions | hash('sha256')", "retained_primary_after.stdout == retained_primary_before.stdout", "kind: relay", "kind: bot", "systemctl, is-active", "recovery_binding_sha256"} {
		if !strings.Contains(text, needed) {
			t.Fatal("missing check: " + needed)
		}
	}
	if strings.LastIndex(text, "Save the fully verified") < strings.Index(text, "Reject changed primary or schema") {
		t.Fatal("result precedes final verification")
	}
}

func TestRetainedPrimaryRebuildFreezesCallerMaps(t *testing.T) {
	in := retainedRebuildFixture(t)
	events := []string{}
	deps := retainedRebuildSuccessfulDependencies(t, in, &events)
	original := deps.Run
	deps.Run = func(ctx context.Context, op string, inv, vars map[string]any, dir, python, exe string) (deployansible.Receipt, error) {
		inv["caller_must_not_change"] = true
		return original(ctx, op, inv, vars, dir, python, exe)
	}
	if err := runRetainedPrimaryRebuild(context.Background(), in, deps); err == nil {
		t.Fatal("accepted runner input drift")
	}
	if _, found := in.Inventory["caller_must_not_change"]; found {
		t.Fatal("runner mutated caller inventory")
	}
}
func TestRetainedPrimaryRebuildRejectsUnsafeReceipt(t *testing.T) {
	dir := retainedRebuildFixture(t).Directory
	target := filepath.Join(dir, "unrelated")
	if err := os.WriteFile(target, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "retained-primary-receipt.json")); err != nil {
		t.Fatal(err)
	}
	if err := publishRetainedPrimaryReceipt(dir, []byte("replace")); err == nil {
		t.Fatal("accepted receipt symlink")
	}
	raw, err := os.ReadFile(target)
	if err != nil || string(raw) != "preserve" {
		t.Fatal("changed unrelated target")
	}
}

func TestRetainedPrimaryRebuildRequiresExactAppliedVersions(t *testing.T) {
	for _, versions := range []string{"1,2", "1,2,3,4", "1,3,2", "01,2,3", "1,2,2", ""} {
		t.Run(versions, func(t *testing.T) {
			in := retainedRebuildFixture(t)
			in.CandidateMigrationVersions = versions
			in.CandidateMigrationsSHA256 = digestSHA256([]byte(versions))
			if err := validateRetainedPrimaryRebuild(in); err == nil {
				t.Fatal("accepted different or malformed candidate migration list")
			}
		})
	}
}

func TestRetainedPrimaryRebuildCanonicalizesTypedVariablesWithoutNumericLoss(t *testing.T) {
	in := retainedRebuildFixture(t)
	in.Variables["metadata"] = struct {
		Z int64  `json:"z"`
		A string `json:"a"`
	}{Z: 9007199254740993, A: "preserve field order semantics"}
	events := []string{}
	deps := retainedRebuildSuccessfulDependencies(t, in, &events)
	run := deps.Run
	deps.Run = func(ctx context.Context, op string, inventory, vars map[string]any, dir, python, exe string) (deployansible.Receipt, error) {
		metadata := vars["metadata"].(map[string]any)
		number, ok := metadata["z"].(json.Number)
		if !ok || number.String() != "9007199254740993" {
			t.Fatal("typed integer lost precision while freezing")
		}
		return run(ctx, op, inventory, vars, dir, python, exe)
	}
	if err := runRetainedPrimaryRebuild(context.Background(), in, deps); err != nil {
		t.Fatal(err)
	}
}
