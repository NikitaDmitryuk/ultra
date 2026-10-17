package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// completeDeploymentFixture supplies the policy required by schema 2 while
// keeping the plan's role endpoints and runtime settings under test.
func completeDeploymentFixture(p *installplan.InstallPlan, release, pins string) {
	p.SchemaVersion = installplan.CurrentSchemaVersion
	address := p.Bridge.Address
	if address == "" {
		address = p.Bridge.SSHHost
	}
	p.Automation = &installplan.AutomationConfig{
		Version:        "v2.5.0",
		ReleaseDir:     release,
		KnownHostsFile: pins,
		AgeRecipient:   "age1fixture",
		BridgeProvider: "bridge-fixture",
		BridgeIPv4:     address,
		BridgeURL:      "https://sync.example.com/healthz",
	}
	for i, e := range p.Exits {
		name := e.Name
		if name == "" {
			name = "primary"
		}
		p.Automation.StaticNodes = append(
			p.Automation.StaticNodes,
			installplan.AutomationNode{
				Name:     name,
				Address:  e.SSHHost,
				Provider: "exit-fixture",
				Budget:   &installplan.StaticBudget{MonthlyBytes: 1000000, IsFallback: i == 0},
			},
		)
	}
	if !p.Bridge.ReuseSpec {
		p.Bot.Enabled = true
		p.Bot.Domain = "sync.example.com"
		p.Automation.Ingress = &installplan.AutomationIngress{Domain: "edge.example.com", Email: "owner@example.com", Path: "/connect"}
	}
}

func TestBootstrapRetryRetainsGeneratedIdentities(t *testing.T) {
	directory := t.TempDir()
	binary := filepath.Join(directory, "ultra-relay-linux-amd64")
	if err := os.WriteFile(binary, []byte("pinned-test-artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ultra-bot-linux-amd64", "secrets.env"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("TELEGRAM_BOT_TOKEN=fixture\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	plan := func() *installplan.InstallPlan {
		p := installplan.LegacyValuesToPlan(
			map[string]string{
				"BRIDGE_IP":         "192.0.2.1",
				"MAIN_EXIT_IP":      "192.0.2.2",
				"REALITY_DEST":      "example.com:443",
				"REUSE_BRIDGE_SPEC": "false",
				"DATABASE_IP":       "192.0.2.40",
				"SKIP_GEO_DOWNLOAD": "true",
			},
		)
		completeDeploymentFixture(p, directory, "/pins")
		p.Secrets.EnvFile = filepath.Join(directory, "secrets.env")
		p.Artifacts.RelayBinary = binary
		return p
	}
	inventory := func() map[string]any {
		return map[string]any{
			"all": map[string]any{
				"vars": map[string]any{},
				"children": map[string]any{
					"databases": map[string]any{"hosts": map[string]any{"database": map[string]any{}}},
					"bridge":    map[string]any{"hosts": map[string]any{"bridge": map[string]any{}}},
					"exits":     map[string]any{"hosts": map[string]any{"exit_0": map[string]any{}}},
				},
			},
		}
	}
	inspection := map[string]bootstrapInspection{"bridge": {Architecture: "amd64"}, "exit_0": {Architecture: "amd64"}}
	first, err := freezeBootstrapInventory(plan(), inventory(), inspection, directory)
	if err != nil {
		t.Fatal(err)
	}
	partialInspection := map[string]bootstrapInspection{}
	for alias, value := range inspection {
		partialInspection[alias] = value
	}
	rawPartial, _ := json.Marshal(
		map[string]any{
			"architecture": "amd64",
			"files": []map[string]string{
				{"source": "/etc/ultra-relay/spec.json", "content": base64.StdEncoding.EncodeToString([]byte(`{"role":"bridge"}`))},
			},
		},
	)
	var partial bootstrapInspection
	if err = json.Unmarshal(rawPartial, &partial); err != nil {
		t.Fatal(err)
	}
	partialInspection["bridge"] = partial // spec installed, environment not installed before crash
	retry, err := freezeBootstrapInventory(plan(), inventory(), partialInspection, directory)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(retry)
	if string(a) != string(b) {
		t.Fatal("retry changed generated relay, route or database identity")
	}
	info, err := os.Stat(filepath.Join(directory, "inventory.frozen.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("frozen secrets are not private")
	}
}

func TestFreshBootstrapDoesNotReusePartialBridgeSpec(t *testing.T) {
	p := installplan.LegacyValuesToPlan(map[string]string{
		"INSTALL_SCHEMA_VERSION": "2",
		"BRIDGE_IP":              "192.0.2.1",
		"MAIN_EXIT_IP":           "192.0.2.2",
		"VLESS_PORT":             "24443",
		"REALITY_DEST":           "example.com:443",
		"REUSE_BRIDGE_SPEC":      "false",
		"DATABASE_IP":            "192.0.2.40",
		"SKIP_GEO_DOWNLOAD":      "true",
		"MAIN_EXIT_DOMAIN":       "gateway.example.com",
		"DNS_PROVIDER":           "vultr",
		"DNS_ZONE":               "example.com",
		"BOT_DOMAIN":             "sync.example.com",
		"VPN_DOMAIN":             "edge.example.com",
		"ACME_EMAIL":             "owner@example.com",
	})
	completeDeploymentFixture(p, "/release", "/pins")
	p.Automation.DNS = &installplan.AutomationDNS{
		Provider: "vultr", Zone: "example.com", TTL: 300,
		SubscriptionName: "sync", VPNName: "edge",
	}
	inspection := bootstrapInspection{}
	raw, err := json.Marshal(map[string]any{"files": []map[string]string{{
		"source":  "/etc/ultra-relay/spec.json",
		"content": base64.StdEncoding.EncodeToString([]byte(`{"role":"bridge"}`)),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &inspection); err != nil {
		t.Fatal(err)
	}
	options, err := bootstrapRenderOptions(p, map[string]bootstrapInspection{"bridge": inspection})
	if err != nil {
		t.Fatal(err)
	}
	if p.Bridge.ReuseSpec || options.ExistingBridge != nil {
		t.Fatal("explicit fresh bootstrap reused a partial bridge specification")
	}
	if _, err = installplan.RenderDesiredStateWithOptions(p, options); err != nil {
		t.Fatalf("managed TLS fresh bootstrap rejected partial bridge state: %v", err)
	}
}

func TestBootstrapStateRejectsForeignOrPublicDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "public")
	if err := os.Mkdir(directory, 0755); err != nil {
		t.Fatal(err)
	}
	if ensurePrivateBootstrapDirectory(directory) == nil {
		t.Fatal("public state accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(directory, link); err != nil {
		t.Fatal(err)
	}
	if ensurePrivateBootstrapDirectory(link) == nil {
		t.Fatal("symlink state accepted")
	}
}

func TestBootstrapAttemptFreshAfterTotalSuccess(t *testing.T) {
	root := t.TempDir()
	first, err := beginBootstrapAttempt(root)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := beginBootstrapAttempt(root)
	if err != nil {
		t.Fatal(err)
	}
	if retry != first {
		t.Fatal("unfinished bootstrap did not resume original attempt")
	}
	if err = completeBootstrapAttempt(root, first); err != nil {
		t.Fatal(err)
	}
	fresh, err := beginBootstrapAttempt(root)
	if err != nil {
		t.Fatal(err)
	}
	if fresh == first {
		t.Fatal("successful receipt reused instead of inspecting new invocation")
	}
	if _, err = os.Stat(first); err != nil {
		t.Fatal("prior immutable operation was deleted")
	}
}

func TestBootstrapRetainsUnrelatedRuntimeReferences(t *testing.T) {
	previous := "ULTRA_RELAY_LOG_LEVEL=warning\nULTRA_REPLICATION_KEY_FILE=/private/replication\nCUSTOM_RUNTIME_PATH=/private/custom\nULTRA_RELAY_ADMIN_TOKEN=old\n"
	desired := "ULTRA_RELAY_ADMIN_TOKEN=retained\nULTRA_RELAY_LOG_LEVEL=info\n"
	merged := mergeBootstrapEnvironment(previous, desired)
	if merged != "CUSTOM_RUNTIME_PATH=/private/custom\n"+desired {
		t.Fatal("runtime references lost or owned keys duplicated")
	}
}

func TestBootstrapDedicatedDatabaseInventory(t *testing.T) {
	pins := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(pins, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ULTRA_INSTALL_SSH_KNOWN_HOSTS", pins)
	p := installplan.LegacyValuesToPlan(
		map[string]string{
			"BRIDGE_IP":         "192.0.2.1",
			"MAIN_EXIT_IP":      "192.0.2.2",
			"BRIDGE_SSH_KEY":    "/keys/vpn",
			"MAIN_EXIT_SSH_KEY": "/keys/exit",
			"DATABASE_IP":       "192.0.2.40",
			"SSH_USER":          "db-admin",
			"DATABASE_SSH_KEY":  "/keys/db",
		},
	)
	completeDeploymentFixture(p, "/release", pins)
	inventory, err := bootstrapInventory(p, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	children := inventory["all"].(map[string]any)["children"].(map[string]any)
	dbs := children["databases"].(map[string]any)["hosts"].(map[string]any)
	if len(dbs) != 1 {
		t.Fatal("expected one dedicated DB host")
	}
	db := dbs["database"].(map[string]any)
	if db["ansible_host"] != "192.0.2.40" || db["ansible_user"] != "db-admin" || db["ansible_ssh_private_key_file"] != "/keys/db" {
		t.Fatal("dedicated database SSH target lost")
	}
	if _, ok := dbs["bridge"]; ok {
		t.Fatal("database provisioned on VPN bridge")
	}
}

func TestUpgradeInventoryExcludesDedicatedDatabaseHost(t *testing.T) {
	pins := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(pins, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ULTRA_INSTALL_SSH_KNOWN_HOSTS", pins)
	p := installplan.LegacyValuesToPlan(map[string]string{
		"BRIDGE_IP":         "192.0.2.1",
		"MAIN_EXIT_IP":      "192.0.2.2",
		"BRIDGE_SSH_KEY":    "/keys/vpn",
		"MAIN_EXIT_SSH_KEY": "/keys/exit",
		"DATABASE_IP":       "192.0.2.40",
		"DATABASE_SSH_KEY":  "/keys/db",
	})
	completeDeploymentFixture(p, "/release", pins)

	inventory, err := upgradeInventory(p, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	children := inventory["all"].(map[string]any)["children"].(map[string]any)
	databases := children["databases"].(map[string]any)["hosts"].(map[string]any)
	if len(databases) != 0 || !p.Database.Enabled {
		t.Fatal("upgrade inventory must exclude the DB host without changing the frozen database plan")
	}
}

func TestBootstrapSeparateRoleIdentitiesWithoutSharedKey(t *testing.T) {
	pins := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(pins, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ULTRA_INSTALL_SSH_KNOWN_HOSTS", pins)
	p := installplan.LegacyValuesToPlan(
		map[string]string{
			"BRIDGE_IP":         "192.0.2.10",
			"MAIN_EXIT_IP":      "192.0.2.20",
			"DATABASE_IP":       "192.0.2.40",
			"BRIDGE_SSH_KEY":    "/keys/bridge",
			"MAIN_EXIT_SSH_KEY": "/keys/exit",
			"DATABASE_SSH_KEY":  "/keys/database",
		},
	)
	completeDeploymentFixture(p, "/release", pins)
	inventory, err := bootstrapInventory(p, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	all := inventory["all"].(map[string]any)
	children := all["children"].(map[string]any)
	if all["vars"].(map[string]any)["ansible_ssh_private_key_file"] != "/keys/bridge" {
		t.Fatal("bridge key lost")
	}
	exit := children["exits"].(map[string]any)["hosts"].(map[string]any)["exit_0"].(map[string]any)
	database := children["databases"].(map[string]any)["hosts"].(map[string]any)["database"].(map[string]any)
	if exit["ansible_ssh_private_key_file"] != "/keys/exit" || database["ansible_ssh_private_key_file"] != "/keys/database" {
		t.Fatal("role keys substituted")
	}
}
