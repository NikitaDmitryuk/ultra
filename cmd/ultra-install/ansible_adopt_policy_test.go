package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func adoptionPolicyFixture(t *testing.T) (*installplan.InstallPlan, bootstrapInspection) {
	t.Helper()
	p, err := installplan.CanonicalValuesToPlan(map[string]string{"BRIDGE": "192.0.2.1", "EXIT": "192.0.2.2", "IDENTITY": "/identity", "BOT_ENV_FILE": "/private/secrets.env", "EXIT_TUNNEL_UUID": "preserved-tunnel", "GENERATE_EXIT_TLS": "false", "EXIT_TLS_CERT_FILE": "/private/exit.crt", "EXIT_TLS_KEY_FILE": "/private/exit.key", "BRIDGE_SSH_HOST": "192.0.2.10", "ULTRA_INSTALL_SSH_STRICT_HOST_KEY": "true", "ULTRA_AUTOMATION_KNOWN_HOSTS_FILE": "/pins", "PUBLIC_HOST": "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	nodes := []installplan.AutomationNode{{Name: "primary", Address: "192.0.2.2", Provider: "exit-provider", Budget: &installplan.StaticBudget{MonthlyBytes: 1000000, IsFallback: true}}}
	documents := map[string]any{
		"deployment.json": map[string]any{"version": "v1.0.0", "controller_directory": "/opt/ultra-ansible/releases/v1.0.0", "bridge_ipv4": "192.0.2.1", "bridge_provider": "bridge-provider", "bridge_url": "https://sync.example.com/healthz", "database": "ultra_db", "static_nodes": nodes, "ingress": installplan.AutomationIngress{Domain: "edge.example.com", Email: "owner@example.com", Path: "/connect", PublicHost: "192.0.2.1", BackendPort: 19080, GatewayPort: 19081, StatusPort: 19082, ExperimentalPort: 6543, StagingPort: 19443}},
		"backup.json":     map[string]any{"source": "bridge", "database": "ultra_db", "recipient": "age1fixture", "state_paths": []string{"/etc/ultra-relay", "/srv/operator-data", "/etc/letsencrypt/live/edge.example.com"}, "artifact_paths": []string{"/usr/local/bin/ultra-install", "/opt/ultra-recovery/reconcile.py", "/opt/ultra-ansible/releases/v1.0.0", "/srv/operator-artifacts"}},
		"reconcile.json":  map[string]any{"database": "ultra_db", "bridge_provider": "bridge-provider", "bridge_url": "https://sync.example.com/healthz", "static_nodes": nodes},
		"dns.json":        map[string]any{"config": map[string]any{"provider": "vultr", "zone": "example.com", "ttl": 300, "subscription_name": "sync", "vpn_name": "edge", "api_key_file": "/etc/ultra-recovery/dns-api-key"}},
	}
	// Legacy canonical bot policy already describes the subscription role.
	p.SourceValues["SUBSCRIPTION_DOMAIN"] = "sync.example.com"
	var inspection bootstrapInspection
	for name, value := range documents {
		raw, _ := json.Marshal(value)
		adoptionInspectionAdd(&inspection, name, raw)
	}
	adoptionInspectionAdd(&inspection, "admin-chat-id", []byte("123\n"))
	return p, inspection
}
func adoptionInspectionAdd(i *bootstrapInspection, name string, raw []byte) {
	i.Files = append(i.Files, struct {
		Content string `json:"content"`
		Source  string `json:"source"`
	}{base64.StdEncoding.EncodeToString(raw), "/etc/ultra-recovery/" + name})
}
func TestPrepareAdoptionPolicyPreservesCanonicalInputs(t *testing.T) {
	p, i := adoptionPolicyFixture(t)
	original := map[string]string{}
	for k, v := range p.SourceValues {
		original[k] = v
	}
	candidate, raw, err := prepareAdoptionConfig(p, i, "v2", "/release", "/pins")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original, p.SourceValues) || p.Automation != nil {
		t.Fatal("source mutated")
	}
	for key, value := range original {
		if candidate.SourceValues[key] != value {
			t.Fatalf("lost canonical input %s", key)
		}
	}
	a := candidate.Automation
	if a.StaticNodes[0].Budget.MonthlyBytes != 1000000 || !a.StaticNodes[0].Budget.IsFallback || candidate.SecretsEnvFile() != "/private/secrets.env" || a.Ingress.BackendPort != 19080 || a.Ingress.StagingPort != 19443 || a.DNS.APIKeyFile != "" || a.AdminTelegramID != 123 {
		t.Fatal("policy was not preserved")
	}
	if !reflect.DeepEqual(a.ArtifactPaths, []string{"/srv/operator-artifacts"}) || !reflect.DeepEqual(a.StatePaths, []string{"/srv/operator-data", "/etc/letsencrypt/live/edge.example.com"}) {
		t.Fatal("baseline filtered incorrectly")
	}
	path := filepath.Join(t.TempDir(), "candidate")
	if err := writeAdoptionCandidate(path, raw); err != nil {
		t.Fatal(err)
	}
	loaded, err := installplan.LoadConfig(path)
	if err != nil || loaded.SchemaVersion != 2 || !reflect.DeepEqual(loaded.Automation.Ingress, a.Ingress) {
		t.Fatal("canonical round trip lost ports")
	}
	for key, value := range original {
		if loaded.SourceValues[key] != value {
			t.Fatalf("canonical round trip lost input %s", key)
		}
	}
	if loaded.Automation.KnownHostsFile != "/pins" || loaded.Features.GenerateExitTLS {
		t.Fatal("canonical round trip changed pins or TLS policy")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("candidate not private")
	}
	if writeAdoptionCandidate(path, []byte("overwrite")) == nil {
		t.Fatal("overwrote existing candidate")
	}
}
func TestPrepareAdoptionPolicyFailsClosed(t *testing.T) {
	for _, name := range []string{"deployment.json", "backup.json", "reconcile.json", "admin-chat-id"} {
		t.Run(name, func(t *testing.T) {
			p, i := adoptionPolicyFixture(t)
			for n := range i.Files {
				if filepath.Base(i.Files[n].Source) == name {
					i.Files[n].Content = base64.StdEncoding.EncodeToString([]byte("invalid-private-fixture"))
				}
			}
			if _, _, err := prepareAdoptionConfig(p, i, "v2", "/release", "/pins"); err == nil || err.Error() != "adoption_policy_missing_or_conflicting" {
				t.Fatal("missing safe rejection")
			}
		})
	}
	for _, key := range []string{"BRIDGE", "ULTRA_AUTOMATION_AGE_RECIPIENT", "VPN_DOMAIN", "DNS_ZONE"} {
		t.Run(key, func(t *testing.T) {
			p, i := adoptionPolicyFixture(t)
			if key == "BRIDGE" {
				p.Bridge.Address = "192.0.2.9"
			} else {
				p.SourceValues[key] = "conflict"
			}
			if _, _, err := prepareAdoptionConfig(p, i, "v2", "/release", "/pins"); err == nil {
				t.Fatal("conflict accepted")
			}
		})
	}
	for _, path := range []string{"/", "relative", "/srv/../etc", "/srv/data\nprivate"} {
		if _, err := adoptionBackupExtras([]string{path}); err == nil {
			t.Fatal("unsafe path accepted")
		}
	}
}

func TestAdoptionMetadataRejectsUnknownPolicy(t *testing.T) {
	for _, raw := range []string{
		`{"version":"v1","unexpected_policy":"private-fixture"}`,
		`{"static_nodes":[{"name":"primary","address":"192.0.2.2","provider":"a","quota_policy":"unknown"}]}`,
		`{"static_nodes":[{"name":"primary","address":"192.0.2.2","provider":"a","budget":{"monthly_bytes":1,"unknown":true}}]}`,
		`{"ingress":{"domain":"edge.example.com","unknown":true}}`,
	} {
		if validAdoptionMetadata("deployment.json", []byte(raw)) {
			t.Fatal("unknown metadata accepted")
		}
	}
	if validAdoptionMetadata("dns.json", []byte(`{"config":{"provider":"vultr","unknown":true}}`)) {
		t.Fatal("unknown DNS policy accepted")
	}
}

func TestAdoptionBackupExtrasPreservesCustomManagedDirectoryMembers(t *testing.T) {
	custom := []string{
		"/opt/ultra-recovery/operator-hook.py",
		"/opt/ultra-recovery/operator-hook.service",
		"/opt/ultra-recovery/release-manifest.json.operator",
		"/etc/systemd/system/ultra-recovery-operator.service",
		"/etc/systemd/system/ultra-monitor-custom.timer",
		"/opt/ultra-ansible",
		"/opt/ultra-ansible/operator-data",
		"/opt/ultra-ansible/releases/v0.9.0",
		"/opt/ultra-recovery/releases",
		"/opt/ultra-recovery/releases/v0.9.0",
	}
	paths := append([]string{"/opt/ultra-recovery/reconcile.py", "/etc/systemd/system/ultra-recovery-backup.timer"}, custom...)
	got, err := adoptionBackupExtras(paths)
	if err != nil || !reflect.DeepEqual(got, custom) {
		t.Fatalf("custom backup coverage lost: got %v, err %v", got, err)
	}
}

func TestPrepareAdoptionPolicyRetainsCustomBackupCoverage(t *testing.T) {
	p, i := adoptionPolicyFixture(t)
	custom := []string{"/opt/ultra-recovery/operator-hook.py", "/opt/ultra-ansible/operator-data", "/opt/ultra-ansible/releases/v0.9.0"}
	for n := range i.Files {
		if filepath.Base(i.Files[n].Source) != "backup.json" {
			continue
		}
		raw, _ := base64.StdEncoding.DecodeString(i.Files[n].Content)
		var backup map[string]any
		if err := json.Unmarshal(raw, &backup); err != nil {
			t.Fatal(err)
		}
		paths := backup["artifact_paths"].([]any)
		for _, path := range custom {
			paths = append(paths, path)
		}
		backup["artifact_paths"] = paths
		raw, _ = json.Marshal(backup)
		i.Files[n].Content = base64.StdEncoding.EncodeToString(raw)
	}
	candidate, raw, err := prepareAdoptionConfig(p, i, "v2", "/release", "/pins")
	if err != nil {
		t.Fatal(err)
	}
	expected := append([]string{"/srv/operator-artifacts"}, custom...)
	if !reflect.DeepEqual(candidate.Automation.ArtifactPaths, expected) {
		t.Fatalf("coverage changed: %v", candidate.Automation.ArtifactPaths)
	}
	path := filepath.Join(t.TempDir(), "candidate")
	if err := writeAdoptionCandidate(path, raw); err != nil {
		t.Fatal(err)
	}
	loaded, err := installplan.LoadConfig(path)
	if err != nil || !reflect.DeepEqual(loaded.Automation.ArtifactPaths, expected) {
		t.Fatalf("round trip changed coverage: %v", err)
	}
}

func TestPrepareAdoptionPolicyRejectsAmbiguousController(t *testing.T) {
	for _, controller := range []string{"/opt/ultra-ansible", "/srv/operator-data", "/opt/ultra-ansible/releases/v0.9.0", "/opt/ultra-ansible/releases/v1.0.0/custom"} {
		t.Run(controller, func(t *testing.T) {
			p, i := adoptionPolicyFixture(t)
			for n := range i.Files {
				if filepath.Base(i.Files[n].Source) != "deployment.json" {
					continue
				}
				raw, _ := base64.StdEncoding.DecodeString(i.Files[n].Content)
				var deployment map[string]any
				if err := json.Unmarshal(raw, &deployment); err != nil {
					t.Fatal(err)
				}
				deployment["controller_directory"] = controller
				raw, _ = json.Marshal(deployment)
				i.Files[n].Content = base64.StdEncoding.EncodeToString(raw)
			}
			if _, _, err := prepareAdoptionConfig(p, i, "v2", "/release", "/pins"); err == nil {
				t.Fatal("ambiguous controller accepted")
			}
		})
	}
}
