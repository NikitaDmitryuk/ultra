package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func operatorStateArgsForCurrentTest(t *testing.T) []string {
	t.Helper()
	if os.Geteuid() == 0 {
		return nil
	}
	state, err := deployansible.ExpectedLocalExecutionState()
	if err != nil {
		t.Fatal(err)
	}
	return []string{"--operator-state-dir", state}
}

func TestLifecycleCLIProcess(t *testing.T) {
	if raw := os.Getenv("ULTRA_LIFECYCLE_TEST_ARGS"); raw != "" {
		var args []string
		if err := json.Unmarshal([]byte(raw), &args); err != nil {
			t.Fatal(err)
		}
		if !handlePlanSubcommand(args) {
			t.Fatal("unhandled fixture command")
		}
		return
	}
}

func lifecycleCLIFixture(t *testing.T) (string, []byte) {
	t.Helper()
	root := t.TempDir()
	secrets := filepath.Join(root, "synthetic-bot-token")
	if err := os.WriteFile(secrets, []byte("TELEGRAM_BOT_TOKEN=fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "install.config")
	raw := []byte(`INSTALL_SCHEMA_VERSION=2
BRIDGE_IP=192.0.2.1
MAIN_EXIT_IP=192.0.2.2
DATABASE_IP=192.0.2.30
BOT_ENABLE=true
REUSE_BRIDGE_SPEC=false
REALITY_DEST=example.com:443
BOT_DOMAIN=sync.example.com
VPN_DOMAIN=edge.example.com
VLESS_PORT=24443
ACME_EMAIL=owner@example.com
PUBLIC_XHTTP_PATH=/connect
DNS_PROVIDER=vultr
DNS_ZONE=example.com
ULTRA_AUTOMATION_VERSION=v2.3.1
ULTRA_AUTOMATION_RELEASE_DIR=/missing/lifecycle-fixture-release
ULTRA_AUTOMATION_AGE_RECIPIENT=age1fixture
ULTRA_AUTOMATION_BRIDGE_PROVIDER=fixture
ULTRA_AUTOMATION_KNOWN_HOSTS_FILE=/pins
ULTRA_AUTOMATION_ADMIN_TELEGRAM_ID=123
ULTRA_AUTOMATION_STATIC_NODES='[{"name":"fixture","address":"192.0.2.2","provider":"fixture"}]'
` + "DATABASE_DUMP=" + filepath.Join(root, "missing-bootstrap.dump") + "\nSECRETS_ENV_FILE=" + secrets + "\n")
	if err := os.WriteFile(config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return config, raw
}

func lifecycleCLI(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	raw, _ := json.Marshal(args)
	cmd := exec.Command(os.Args[0], "-test.run=^TestLifecycleCLIProcess$")
	cmd.Env = append(os.Environ(), "ULTRA_LIFECYCLE_TEST_ARGS="+string(raw))
	return cmd.CombinedOutput()
}

func TestLifecycleCLIPlanAndDoctorIgnoreLocalBootstrapArchive(t *testing.T) {
	config, _ := lifecycleCLIFixture(t)
	for _, command := range []string{"plan", "doctor"} {
		out, err := lifecycleCLI(t, command, "--config", config, "--lifecycle", "--format", "json")
		if err != nil || strings.Contains(string(out), "missing-bootstrap.dump") {
			t.Fatalf("%s lifecycle failed or leaked archive: %s %v", command, out, err)
		}
		out, err = lifecycleCLI(t, command, "--config", config, "--format", "json")
		if err == nil || !strings.Contains(string(out), "DATABASE_DUMP must be a private regular custom archive") {
			t.Fatalf("%s bootstrap stopped validating archive: %s %v", command, out, err)
		}
	}
}

func TestLifecycleCLIUpgradeStatusAndRepairSafeLocalBoundaries(t *testing.T) {
	config, raw := lifecycleCLIFixture(t)
	upgradeArgs := []string{"operator-upgrade", "--config", config, "--release-dir", "/missing/lifecycle-fixture-release",
		"--source-commit", strings.Repeat("a", 40), "--version", "v2.3.1",
		"--manifest-sha256", strings.Repeat("b", 64), "--config-sha256", digestSHA256(raw)}
	upgradeArgs = append(upgradeArgs, operatorStateArgsForCurrentTest(t)...)
	if os.Geteuid() != 0 {
		upgradeArgs = append(upgradeArgs, "--job-dir", filepath.Join(filepath.Dir(config), "job"))
	}
	for _, args := range [][]string{
		upgradeArgs,
		{"status", "--config", config, "--ansible-playbook", "/missing/lifecycle-fixture-ansible"},
		{"recovery-tools-bootstrap", "--config", config, "--release-dir", "/missing/lifecycle-fixture-release",
			"--version", "v2.3.1", "--candidate-sha256", strings.Repeat("b", 64), "--manual-consumers-excluded"},
	} {
		if args[0] == "operator-upgrade" || args[0] == "status" {
			args = append(args, "--lifecycle")
		}
		out, err := lifecycleCLI(t, args...)
		if err == nil || strings.Contains(string(out), "DATABASE_DUMP") || strings.Contains(string(out), "explicit traffic budgets") {
			t.Fatalf("%s did not reach safe local lifecycle boundary: %s %v", args[0], out, err)
		}
		want := map[string]string{"operator-upgrade": "operator upgrade release verification:",
			"status": "ansible executable unavailable", "recovery-tools-bootstrap": "bootstrap_must_execute_on_attested_bridge"}[args[0]]
		if !strings.Contains(string(out), want) {
			t.Fatalf("%s failed at unexpected boundary: %s", args[0], out)
		}
	}
}

func TestLifecycleCLIPlansCannotEnterBootstrapOrApply(t *testing.T) {
	config, _ := lifecycleCLIFixture(t)
	p, err := installplan.LoadLifecycleConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	plan := filepath.Join(t.TempDir(), "lifecycle-plan.json")
	raw, _ := json.Marshal(p)
	if err = os.WriteFile(plan, raw, 0600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"bootstrap", "apply", "apply-remote", "render"} {
		args := []string{command, "--plan", plan}
		if command == "render" {
			args = append(args, "--out", filepath.Join(t.TempDir(), "rendered"))
		}
		out, err := lifecycleCLI(t, args...)
		if err == nil || !strings.Contains(string(out), "lifecycle plan cannot be used for bootstrap or apply") {
			t.Fatalf("%s accepted lifecycle plan or failed late: %s %v", command, out, err)
		}
	}
}

func TestLifecycleFrozenIdentityPreservesLegacyPolicy(t *testing.T) {
	config, _ := lifecycleCLIFixture(t)
	p, err := installplan.LoadLifecycleConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	legacy := *p
	legacy.LifecycleOnly = false
	dir := t.TempDir()
	if err = freezeOperatorPlan(dir, &legacy, "/release"); err != nil {
		t.Fatal(err)
	}
	if err = matchOperatorPlan(dir, p, "/release"); err != nil {
		t.Fatalf("invocation context changed historical policy identity: %v", err)
	}
	p.Database.PrimaryHost = "192.0.2.31"
	if matchOperatorPlan(dir, p, "/release") == nil {
		t.Fatal("policy change hidden by lifecycle normalization")
	}
	legacy.Secrets.DatabaseDumpFile = "/private/legacy-bootstrap.dump"
	legacy.Secrets.DatabaseDumpSHA256 = strings.Repeat("c", 64)
	oldHash, _ := operatorPlanDigest(&legacy, "/release")
	projectedHash, _ := operatorPlanDigest(installplan.LifecycleProjection(&legacy), "/release")
	if oldHash == projectedHash {
		t.Fatal("historical dump-bound operation silently reinterpreted")
	}
}
