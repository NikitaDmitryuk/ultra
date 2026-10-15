package installplan

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
)

// completePlanFixture supplies deployment policy for renderer and doctor tests.
// Clean installations require a bot, a dedicated database and ingress as well.
func completePlanFixture(p *InstallPlan) *InstallPlan {
	p.SchemaVersion = CurrentSchemaVersion
	address := p.Bridge.Address
	if address == "" {
		address = p.Bridge.SSHHost
	}
	p.Automation = &AutomationConfig{Version: "v2.3.4", ReleaseDir: "/release", AgeRecipient: "age1fixture", BridgeProvider: "bridge-fixture", BridgeIPv4: address, BridgeURL: "https://sync.example.com/healthz", KnownHostsFile: "/pins"}
	for i, e := range p.Exits {
		name := e.Name
		if name == "" {
			name = "primary"
		}
		p.Automation.StaticNodes = append(p.Automation.StaticNodes, AutomationNode{Name: name, Address: e.SSHHost, Provider: "exit-fixture", Budget: &StaticBudget{MonthlyBytes: 1000000, IsFallback: i == 0}})
	}
	if !p.Bridge.ReuseSpec {
		p.Bot.Enabled = true
		if p.Bot.Domain == "" {
			p.Bot.Domain = "sync.example.com"
		}
		p.Database.Enabled = true
		if p.Database.PrimaryHost == "" {
			p.Database.PrimaryHost = "192.0.2.40"
		}
		p.Automation.Ingress = &AutomationIngress{Domain: "edge.example.com", Email: "owner@example.com", Path: "/connect"}
	}
	return p
}

func TestLegacyValuesToPlanMapsExitPair(t *testing.T) {
	p := LegacyValuesToPlan(map[string]string{
		"BRIDGE_IP":      "203.0.113.10",
		"MAIN_EXIT_IP":   "203.0.113.11",
		"SSH_USER":       "root",
		"BRIDGE_SSH_KEY": "/tmp/key",
		"REALITY_DEST":   "www.microsoft.com:443",
		"DATABASE_IP":    "192.0.2.40",
		"BOT_ENABLE":     "y",
		"BOT_DOMAIN":     "admin.example.com",
	})
	completePlanFixture(p)
	if err := ValidatePlan(p); err != nil {
		t.Fatalf("ValidatePlan: %v", err)
	}
	if len(p.Exits) != 1 {
		t.Fatalf("exits len = %d, want 2", len(p.Exits))
	}
	if p.Exits[0].Name != "primary" || p.Exits[0].Priority != 100 {
		t.Fatalf("primary exit = %#v", p.Exits[0])
	}
	if !p.Database.Enabled {
		t.Fatal("database should be enabled")
	}
	if !p.Bot.Enabled || p.Bot.Domain != "admin.example.com" {
		t.Fatalf("bot = %#v", p.Bot)
	}
	if p.Secrets.EnvFile != ".env" {
		t.Fatalf("secrets env file = %q, want .env", p.Secrets.EnvFile)
	}
}

func TestConfigSeparatesBridgeAddressFromSSHTarget(t *testing.T) {
	p := LegacyValuesToPlan(map[string]string{
		"BRIDGE_IP": "192.0.2.10",

		"MAIN_EXIT_IP": "192.0.2.20",
		"REALITY_DEST": "origin.example.net:443",
		"BOT_ENABLE":   "yes",
		"BOT_DOMAIN":   "sync.example.com",
	})
	completePlanFixture(p)
	if err := ValidatePlan(p); err != nil {
		t.Fatal(err)
	}
	if p.Bridge.Address != "192.0.2.10" || p.Bridge.SSHHost != "192.0.2.10" {
		t.Fatalf("bridge address and SSH target were conflated: %#v", p.Bridge)
	}
	if p.Bridge.PublicHost != "192.0.2.10" {
		t.Fatalf("public host = %q, want service address", p.Bridge.PublicHost)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("TELEGRAM_BOT_TOKEN=fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var sshTargets []string
	var dialTargets []string
	report := Doctor(context.Background(), p, DoctorOptions{
		CheckSSH: func(_, host, _ string) bool {
			sshTargets = append(sshTargets, host)
			return true
		},
		LookupHost: func(context.Context, string) ([]string, error) {
			return []string{"192.0.2.10"}, nil
		},
		DialTCP: func(_ context.Context, host string, _ int) error {
			dialTargets = append(dialTargets, host)
			return nil
		},
		EnvRoot: dir,
	})
	if !report.OK {
		t.Fatalf("doctor failed: %#v", report.Issues)
	}
	if len(sshTargets) != 2 || sshTargets[0] != "192.0.2.10" || sshTargets[1] != "192.0.2.20" {
		t.Fatalf("doctor SSH targets = %v", sshTargets)
	}
	if len(dialTargets) != 2 || dialTargets[0] != "192.0.2.10" || dialTargets[1] != "192.0.2.10" {
		t.Fatalf("doctor service targets = %v", dialTargets)
	}
}

func TestRenderDesiredStateSupportsManyExits(t *testing.T) {
	p := &InstallPlan{
		SchemaVersion: CurrentSchemaVersion,
		SSH:           SSHConfig{User: "root"},
		Bridge: BridgeConfig{
			SSHHost:     "203.0.113.10",
			PublicHost:  "203.0.113.10",
			VLESSPort:   443,
			TunnelPort:  8443,
			RealityDest: "www.microsoft.com:443",
			RemoteDir:   "/etc/ultra-relay",
		},
		Exits: []ExitNode{
			{Name: "primary", SSHHost: "203.0.113.11", DialAddr: "exit1.example.com", Priority: 100},
			{Name: "backup", SSHHost: "203.0.113.12", Priority: 200},
			{Name: "third", SSHHost: "203.0.113.13", Priority: 300},
		},
		Features: FeatureConfig{
			Preset:          "apijson",
			Transport:       "splithttp",
			LogLevel:        "info",
			GenerateExitTLS: true,
		},
	}
	completePlanFixture(p)
	ds, err := RenderDesiredState(p)
	if err != nil {
		t.Fatalf("RenderDesiredState: %v", err)
	}
	if len(ds.ExitSpecs) != 3 {
		t.Fatalf("exit specs len = %d, want 3", len(ds.ExitSpecs))
	}
	if len(ds.Bootstrap) != 3 {
		t.Fatalf("bootstrap len = %d, want 3", len(ds.Bootstrap))
	}
	if ds.Bootstrap[0].Address != "exit1.example.com" {
		t.Fatalf("primary bootstrap address = %q", ds.Bootstrap[0].Address)
	}
	if !ds.Bootstrap[2].EnabledOrDefault() {
		t.Fatal("third exit should default enabled in rendered desired state")
	}
	if ds.BridgeSpecObject.Exit.TunnelUUID != ds.Bootstrap[0].TunnelUUID {
		t.Fatalf("bridge exit uuid %q != bootstrap uuid %q", ds.BridgeSpecObject.Exit.TunnelUUID, ds.Bootstrap[0].TunnelUUID)
	}
}

func TestRenderDesiredStateGeneratesDatabaseDSN(t *testing.T) {
	p := &InstallPlan{
		SchemaVersion: CurrentSchemaVersion,
		SSH:           SSHConfig{User: "root"},
		Bridge: BridgeConfig{
			SSHHost:     "203.0.113.10",
			PublicHost:  "203.0.113.10",
			VLESSPort:   443,
			TunnelPort:  8443,
			RealityDest: "www.microsoft.com:443",
			RemoteDir:   "/etc/ultra-relay",
		},
		Exits: []ExitNode{{Name: "primary", SSHHost: "203.0.113.11", Priority: 100}},
		Features: FeatureConfig{
			Preset:          "apijson",
			Transport:       "splithttp",
			LogLevel:        "info",
			GenerateExitTLS: true,
		},
		Database: DatabaseConfig{Enabled: true, PrimaryHost: "192.0.2.40", Name: "ultra_db", User: "ultra"},
	}
	completePlanFixture(p)
	ds, err := RenderDesiredState(p)
	if err != nil {
		t.Fatalf("RenderDesiredState: %v", err)
	}
	if ds.DBDSN == "" {
		t.Fatal("DBDSN is empty")
	}
	if strings.Contains(ds.DBDSN, "GENERATED_PASSWORD") {
		t.Fatalf("DBDSN still contains placeholder: %s", ds.DBDSN)
	}
	if !strings.Contains(ds.BridgeEnv, "ULTRA_RELAY_DB_DSN="+ds.DBDSN) {
		t.Fatalf("bridge env missing DSN: %q", ds.BridgeEnv)
	}
}

func TestRenderDesiredStateReusePreservesBridgeMaterial(t *testing.T) {
	p := &InstallPlan{
		SchemaVersion: CurrentSchemaVersion,
		SSH:           SSHConfig{User: "root"},
		Bridge: BridgeConfig{
			SSHHost:    "203.0.113.10",
			PublicHost: "203.0.113.10",
			VLESSPort:  443,
			TunnelPort: 8443,
			ReuseSpec:  true,
			RemoteDir:  "/etc/ultra-relay",
		},
		Exits: []ExitNode{{Name: "primary", SSHHost: "203.0.113.11", DialAddr: "exit.example.com", Priority: 100}},
		Features: FeatureConfig{
			Preset:          "apijson",
			Transport:       "splithttp",
			LogLevel:        "info",
			GenerateExitTLS: true,
		},
	}
	existing := &config.Spec{
		SchemaVersion: config.CurrentSpecSchemaVersion,
		Role:          config.RoleBridge,
		MimicPreset:   "steamlike",
		ListenAddress: "0.0.0.0",
		VLESSPort:     443,
		AdminListen:   "127.0.0.1:8443",
		PublicHost:    "203.0.113.10",
		SubscriptionBridges: []config.SubscriptionBridge{
			{ID: "primary", Host: "primary.example.com", Port: 443, PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ServerName: "example.com", ShortID: "ab12"},
			{ID: "backup", Host: "backup.example.com", Port: 8443, PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ServerName: "example.com", Transport: "xhttp", Path: "/vpn"},
		},
		Reality: config.RealitySpec{
			Dest:        "www.microsoft.com:443",
			ServerNames: []string{"www.microsoft.com"},
			PrivateKey:  "private",
			PublicKey:   "public",
			ShortIDs:    []string{""},
			SpiderX:     "/",
		},
		Exit: config.ExitTunnelSpec{
			Address:    "exit.example.com",
			Port:       8443,
			TunnelUUID: "11111111-1111-1111-1111-111111111111",
		},
		SplithttpHost: "reuse.example.com",
		SplithttpPath: "/reused",
		SplitHTTPTLS: config.SplitHTTPTLSSpec{
			ServerName:  "reuse.example.com",
			Alpn:        []string{"h2"},
			Fingerprint: "chrome",
		},
		TunnelTransport: config.TunnelTransportSplitHTTP,
		GeoAssetsDir:    "/etc/ultra-relay/geo",
		GeositeExitTags: []string{"ru-blocked-all"},
	}
	existing.HappDefaultJSON = true
	existing.ProbeURLs = []string{"https://health.example.com/test", "https://health.example.net/test"}
	existing.Stats = &config.StatsSpec{CollectIntervalSeconds: 5, APIListen: "127.0.0.1:10085"}
	p.Database.Enabled = true
	p.Database.PrimaryHost = "192.0.2.40"
	existing.Database = &config.DatabaseSpec{DSN: "postgres://ultra:retained-secret@127.0.0.1:25432/ultra_db?sslmode=disable"}
	completePlanFixture(p)
	ds, err := RenderDesiredStateWithOptions(p, RenderOptions{
		ExistingBridge:     existing,
		ExistingAdminToken: "admin-token",
		PriorBootstrap: []exits.BootstrapEntry{{
			Name:       "primary",
			Address:    "exit.example.com",
			Port:       8443,
			TunnelUUID: "22222222-2222-2222-2222-222222222222",
			Priority:   100,
		}},
	})
	if err != nil {
		t.Fatalf("RenderDesiredStateWithOptions: %v", err)
	}
	if !ds.BridgeSpecObject.HappDefaultJSON || !reflect.DeepEqual(ds.BridgeSpecObject.ProbeURLs, existing.ProbeURLs) || !reflect.DeepEqual(ds.BridgeSpecObject.Stats, existing.Stats) {
		t.Fatal("reuse lost client publication or traffic collection configuration")
	}
	if ds.DBDSN != existing.Database.DSN || ds.BridgeSpecObject.Database.DSN != existing.Database.DSN || ds.PostgresConfig == nil {
		t.Fatal("reuse rotated database credentials or reprovisioned the primary")
	}
	p.Database.Enabled = false
	withoutProvisioning, err := RenderDesiredStateWithOptions(p, RenderOptions{ExistingBridge: existing, ExistingAdminToken: "admin-token"})
	if err != nil {
		t.Fatal(err)
	}
	if withoutProvisioning.DBDSN != existing.Database.DSN {
		t.Fatal("disabling primary provisioning removed existing database access")
	}
	if ds.BridgeSpecObject.Reality.PrivateKey != "private" {
		t.Fatalf("reality private key not reused: %#v", ds.BridgeSpecObject.Reality)
	}
	if !reflect.DeepEqual(ds.BridgeSpecObject.SubscriptionBridges, existing.SubscriptionBridges) {
		t.Fatal("reuse render dropped or changed subscription bridges")
	}
	var rendered config.Spec
	if err := json.Unmarshal(ds.BridgeSpec, &rendered); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rendered.SubscriptionBridges, existing.SubscriptionBridges) {
		t.Fatal("serialized bridge spec lost subscription publication")
	}
	user := auth.User{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee"}
	profile, err := config.BuildHappProfile(&rendered, user, "Автоматически")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := core.LoadConfig("json", bytes.NewReader(data)); err != nil {
		t.Fatal("rendered subscription cannot load in Xray", err)
	}
	for _, raw := range profile["outbounds"].([]any)[1:] {
		out := raw.(map[string]any)
		server := out["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
		credential := server["users"].([]any)[0].(map[string]any)["id"]
		if credential != user.UUID {
			t.Fatal("rendered profile changed user credential")
		}
	}
	ds.BridgeSpecObject.SubscriptionBridges[0].Host = "changed.example.com"
	if existing.SubscriptionBridges[0].Host != "primary.example.com" {
		t.Fatal("rendered publication aliases source slice")
	}
	if ds.SplitHTTPPath != "/reused" || ds.SplitHTTPHost != "reuse.example.com" {
		t.Fatalf("splithttp not reused: host=%q path=%q", ds.SplitHTTPHost, ds.SplitHTTPPath)
	}
	if ds.AdminToken != "admin-token" {
		t.Fatalf("admin token = %q", ds.AdminToken)
	}
	if got := ds.TunnelUUIDs["primary"]; got != "22222222-2222-2222-2222-222222222222" {
		t.Fatalf("tunnel uuid = %q", got)
	}
}

func TestDoctorReportsMissingBotTokenWithoutNetwork(t *testing.T) {
	dir := t.TempDir()
	p := &InstallPlan{
		SchemaVersion: CurrentSchemaVersion,
		SSH:           SSHConfig{User: "root"},
		Bridge: BridgeConfig{
			SSHHost:     "203.0.113.10",
			RealityDest: "www.microsoft.com:443",
		},
		Exits: []ExitNode{{Name: "primary", SSHHost: "203.0.113.11"}},
		Features: FeatureConfig{
			Preset:          "apijson",
			Transport:       "splithttp",
			LogLevel:        "info",
			GenerateExitTLS: true,
		},
		Bot:     BotConfig{Enabled: true, Domain: "admin.example.com"},
		Secrets: SecretsConfig{EnvFile: "ultra-secrets.env"},
	}
	completePlanFixture(p)
	report := Doctor(context.Background(), p, DoctorOptions{EnvRoot: dir})
	if report.OK {
		t.Fatal("doctor should fail without bot token")
	}
	if len(report.Issues) == 0 || report.Issues[0].Code != CodeMissingBotToken {
		t.Fatalf("issues = %#v", report.Issues)
	}

	if err := os.WriteFile(filepath.Join(dir, "ultra-secrets.env"), []byte("TELEGRAM_BOT_TOKEN=token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	report = Doctor(context.Background(), p, DoctorOptions{EnvRoot: dir})
	if !report.OK {
		t.Fatalf("doctor should pass token-only checks: %#v", report.Issues)
	}
}

func TestReusePreservesManagedIngress(t *testing.T) {
	src := &config.Spec{PrimaryXHTTP: &config.PrimaryXHTTPIngress{Host: "vpn.example", BackendPort: 18080}, LegacyPublicEnabled: config.BoolPtr(false), ExperimentalProfileFile: "/etc/ultra-relay/experimental-profile.json", GatewayVLESSPort: 18081}
	dst := new(config.Spec)
	if err := applyBridgeOverlay(dst, src); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dst.PrimaryXHTTP, src.PrimaryXHTTP) || dst.LegacyPublicEnabled == nil || *dst.LegacyPublicEnabled || dst.ExperimentalProfileFile != src.ExperimentalProfileFile || dst.GatewayVLESSPort != 18081 {
		t.Fatal("managed ingress lost during reuse")
	}
}

func TestDedicatedDatabaseRejectsVPNHostsAndReplicas(t *testing.T) {
	for _, values := range []map[string]string{
		{"DATABASE_IP": "192.0.2.1"}, {"DATABASE_IP": "192.0.2.2"},
	} {
		values["BRIDGE_IP"] = "192.0.2.1"
		values["MAIN_EXIT_IP"] = "192.0.2.2"
		p := LegacyValuesToPlan(values)
		completePlanFixture(p)
		if ValidatePlan(p) == nil {
			t.Fatal("accepted unsupported database topology")
		}
	}
}

func TestDedicatedDatabaseUsesTunnelAndExplicitSSHIdentity(t *testing.T) {
	p := LegacyValuesToPlan(map[string]string{"BRIDGE_IP": "192.0.2.1", "MAIN_EXIT_IP": "192.0.2.2", "DATABASE_IP": "192.0.2.40", "SSH_USER": "db-admin", "DATABASE_SSH_KEY": "/keys/db", "BRIDGE_SSH_KEY": "/keys/vpn", "REUSE_BRIDGE_SPEC": "false", "REALITY_DEST": "example.com:443"})
	completePlanFixture(p)
	ds, err := RenderDesiredState(p)
	if err != nil {
		t.Fatal(err)
	}
	if p.Database.SSHIdentity != "/keys/db" || p.Database.SSHUser != "db-admin" {
		t.Fatal("database SSH access lost")
	}
	if !strings.Contains(ds.DBDSN, "@127.0.0.1:25432/") || ds.PostgresConfig == nil {
		t.Fatal("database bypasses dedicated tunnel")
	}
}

func TestRoleSSHIdentities(t *testing.T) {
	p := LegacyValuesToPlan(map[string]string{"BRIDGE_IP": "192.0.2.10", "MAIN_EXIT_IP": "192.0.2.20", "BRIDGE_SSH_KEY": "/keys/bridge", "MAIN_EXIT_SSH_KEY": "/keys/exit"})
	if p.BridgeSSHIdentity() != "/keys/bridge" || p.ExitSSHIdentity(p.Exits[0]) != "/keys/exit" {
		t.Fatal("per-server key lost")
	}
}

func TestPublishedDedicatedInstallPlanExampleValidates(t *testing.T) {
	data, err := os.ReadFile("../../deploy/install-plan-v2.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var p InstallPlan
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePlan(&p); err != nil {
		t.Fatal(err)
	}
	if p.Database.PrimaryHost == p.Bridge.Address || p.Database.SSHIdentity == "" || p.Bridge.SSHIdentity == "" || p.Exits[0].SSHIdentity == "" {
		t.Fatal("example must declare dedicated roles and their SSH keys")
	}
}
