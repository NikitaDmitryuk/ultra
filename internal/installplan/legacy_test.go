package installplan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
)

func TestLegacyValuesToPlanMapsExitPair(t *testing.T) {
	p := LegacyValuesToPlan(map[string]string{
		"BRIDGE":         "203.0.113.10",
		"EXIT":           "203.0.113.11",
		"EXIT2":          "203.0.113.12",
		"EXIT2_NAME":     "backup-eu",
		"EXIT2_PRIORITY": "250",
		"SSH_USER":       "root",
		"IDENTITY":       "/tmp/key",
		"REALITY_DEST":   "www.microsoft.com:443",
		"DB_ENABLE":      "y",
		"BOT_ENABLE":     "y",
		"BOT_DOMAIN":     "admin.example.com",
	})
	if err := ValidatePlan(p); err != nil {
		t.Fatalf("ValidatePlan: %v", err)
	}
	if len(p.Exits) != 2 {
		t.Fatalf("exits len = %d, want 2", len(p.Exits))
	}
	if p.Exits[0].Name != "primary" || p.Exits[0].Priority != 100 {
		t.Fatalf("primary exit = %#v", p.Exits[0])
	}
	if p.Exits[1].Name != "backup-eu" || p.Exits[1].Priority != 250 {
		t.Fatalf("backup exit = %#v", p.Exits[1])
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
		Database: DatabaseConfig{Enabled: true, Name: "ultra_db", User: "ultra"},
	}
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
	if ds.BridgeSpecObject.Reality.PrivateKey != "private" {
		t.Fatalf("reality private key not reused: %#v", ds.BridgeSpecObject.Reality)
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
