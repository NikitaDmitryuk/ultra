package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestRecoveryBootstrapSelectionCoherentAndRetainsAuthenticatedBaseline(t *testing.T) {
	tools := []map[string]any{}
	for _, name := range []string{"recovery.py", "restore_host.py", "restore_database.py", "monitor.py"} {
		tools = append(tools, map[string]any{"destination": "/opt/ultra-recovery/" + name, "previous_sha256": strings.Repeat("a", 64)})
	}
	bridge, err := recoveryBootstrapSelection(tools, true, "/opt/ultra-recovery/releases/v2.3.0", "v2.3.1")
	if err != nil || len(bridge) != 3 {
		t.Fatalf("bridge selection: %v %v", bridge, err)
	}
	if bridge[0]["baseline_controller_source"] != "/opt/ultra-recovery/releases/v2.3.0/recovery.py" ||
		bridge[0]["baseline_source"] != "/var/lib/ultra-ansible/releases/v2.3.1/bootstrap-baseline/recovery.py" {
		t.Fatal("baseline provenance or candidate fallback binding lost")
	}
	exits, err := recoveryBootstrapSelection(tools, false, "/old", "v2.3.1")
	if err != nil || len(exits) != 1 || exits[0]["destination"] != "/opt/ultra-recovery/recovery.py" {
		t.Fatalf("receiver selection: %v %v", exits, err)
	}
	if _, modified := tools[0]["baseline_source"]; modified {
		t.Fatal("selection mutated common release inputs")
	}
	if _, err = recoveryBootstrapSelection(tools[:2], true, "/old", "v2.3.1"); err == nil {
		t.Fatal("accepted partial bridge reader set")
	}
	tools[0]["previous_sha256"] = ""
	if _, err = recoveryBootstrapSelection(tools, false, "/old", "v2.3.1"); err == nil {
		t.Fatal("accepted unverified old baseline")
	}
}

func TestRecoveryBootstrapStablePlanAllowsStagedCandidateOnly(t *testing.T) {
	directory := t.TempDir()
	config := filepath.Join(directory, "install.config")
	base := `INSTALL_SCHEMA_VERSION=2
BRIDGE_IP=192.0.2.1
MAIN_EXIT_IP=192.0.2.2
BOT_DOMAIN=sync.example.com
VPN_DOMAIN=edge.example.com
VLESS_PORT=24443
ACME_EMAIL=owner@example.com
PUBLIC_XHTTP_PATH=/connect
DNS_PROVIDER=vultr
DNS_ZONE=example.com
ULTRA_AUTOMATION_AGE_RECIPIENT=age1fixture
ULTRA_AUTOMATION_BRIDGE_PROVIDER=fixture
ULTRA_AUTOMATION_KNOWN_HOSTS_FILE=/pins
ULTRA_AUTOMATION_ADMIN_TELEGRAM_ID=123
ULTRA_AUTOMATION_STATIC_NODES='[{"name":"fixture","address":"192.0.2.2","provider":"fixture"}]'
`
	load := func(version, release string) *installplan.InstallPlan {
		t.Helper()
		data := base + "ULTRA_AUTOMATION_VERSION=" + version + "\nULTRA_AUTOMATION_RELEASE_DIR=" + release + "\n"
		if err := os.WriteFile(config, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		p, err := installplan.LoadConfig(config)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	a := load("v2.3.1", "/staged/candidate-a")
	if err := freezeOperatorPlan(directory, recoveryBootstrapStablePlan(a), ""); err != nil {
		t.Fatal(err)
	}
	b := load("v2.3.2", "/staged/candidate-b")
	if err := freezeOperatorPlan(directory, recoveryBootstrapStablePlan(b), ""); err != nil {
		t.Fatalf("normal staging candidate update rejected: %v", err)
	}
	if b.Automation.Version != "v2.3.2" || b.Automation.ReleaseDir != "/staged/candidate-b" {
		t.Fatal("normalization mutated actual candidate plan")
	}
	b.Bridge.Address = "192.0.2.99"
	if err := freezeOperatorPlan(directory, recoveryBootstrapStablePlan(b), ""); err == nil {
		t.Fatal("topology drift accepted")
	}
	b = load("v2.3.2", "/staged/candidate-b")
	b.Automation.KnownHostsFile = "/other-pins"
	if err := freezeOperatorPlan(directory, recoveryBootstrapStablePlan(b), ""); err == nil {
		t.Fatal("SSH security policy drift accepted")
	}
}

func TestRecoveryBootstrapRejectsInstalledCandidateGeneration(t *testing.T) {
	installed := []byte(`{"version":"v2.3.0"}`)
	if err := recoveryBootstrapDistinctGeneration("v2.3.0", installed); err == nil {
		t.Fatal("installed immutable generation accepted as repair candidate")
	}
	if err := recoveryBootstrapDistinctGeneration("v2.3.1", installed); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryBootstrapCLIStageExplicitRetry(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python unavailable")
	}
	for _, operation := range []string{"bootstrap-recovery-inspect", "bootstrap-recovery-tools"} {
		t.Run(operation, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			ctx, release, err := deployansible.WithOperationLock(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			executable := filepath.Join(root, "ansible")
			source := "#!" + python + "\n" + `import json,pathlib,sys
job=pathlib.Path(sys.argv[-1][1:]).parent
count=job/'calls'
n=int(count.read_text())+1 if count.exists() else 1
count.write_text(str(n))
if n==1: sys.exit(1)
result=job/'result.json'
result.write_text(json.dumps({'verified':True}))
result.chmod(0o600)
`
			if err := os.WriteFile(executable, withNormalAnsibleFailure(source), 0700); err != nil {
				t.Fatal(err)
			}
			stage := filepath.Join(root, "phase")
			inventory := map[string]any{}
			variables := map[string]any{"ultra_lock_directory": root}
			for i := 0; i < 2; i++ {
				if _, err := runRecoveryBootstrapStage(ctx, false, operation, inventory, variables, stage, python, executable); err == nil {
					t.Fatal("failed phase implicitly retried")
				}
			}
			calls, err := os.ReadFile(filepath.Join(stage, "calls"))
			if err != nil || string(calls) != "1" {
				t.Fatalf("implicit retry calls=%s err=%v", calls, err)
			}
			before, err := os.ReadFile(filepath.Join(stage, "receipt.json"))
			if err != nil {
				t.Fatal(err)
			}
			result, err := runRecoveryBootstrapStage(ctx, true, operation, inventory, variables, stage, python, executable)
			if err != nil || result.Result.Values["verified"] != true {
				t.Fatalf("explicit CLI retry failed: %v", err)
			}
			archived, err := os.ReadFile(filepath.Join(stage, "history", "attempt-1.json"))
			if err != nil || string(archived) != string(before) {
				t.Fatal("explicit retry lost original failed phase")
			}
			calls, err = os.ReadFile(filepath.Join(stage, "calls"))
			if err != nil || string(calls) != "2" {
				t.Fatalf("explicit retry calls=%s err=%v", calls, err)
			}
		})
	}
}
