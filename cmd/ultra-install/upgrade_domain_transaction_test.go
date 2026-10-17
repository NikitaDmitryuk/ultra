package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	recoveryassets "github.com/NikitaDmitryuk/ultra/deploy/recovery"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestUpgradeDomainProbePrivateBoundary(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "probe")
	good := "https://sync.example.com/sub/test-user-token"
	if err := os.WriteFile(path, []byte(good+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := readUpgradeDomainProbe(path, "sync.example.com"); err != nil || got != good {
		t.Fatalf("private input rejected: %v", err)
	}
	for _, bad := range []string{"http://sync.example.com/sub/token", "https://other.example.com/sub/token", "https://sync.example.com:443/sub/token", "https://user@sync.example.com/sub/token", good + "?x=y", good + "#fragment", good + "\nsecond", "https://sync.example.com/sub/a/b", "https://sync.example.com/sub/%74oken", "https://sync.example.com/sub/%0A", "https://sync.example.com/healthz"} {
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readUpgradeDomainProbe(path, "sync.example.com"); err == nil {
			t.Fatal("invalid private probe accepted")
		}
	}
	if err := os.WriteFile(path, []byte(good), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readUpgradeDomainProbe(path, "sync.example.com"); err == nil {
		t.Fatal("public input accepted")
	}
	os.Chmod(path, 0600) //nolint:errcheck
	link := filepath.Join(root, "link")
	os.Symlink(path, link) //nolint:errcheck
	if _, err := readUpgradeDomainProbe(link, "sync.example.com"); err == nil {
		t.Fatal("symlink accepted")
	}
	if _, err := readUpgradeDomainProbe(root, "sync.example.com"); err == nil {
		t.Fatal("directory accepted")
	}
}

func TestUpgradeDomainAuthorizationBoundToEveryDesiredName(t *testing.T) {
	s, request := runtimeHostFixture(t)
	in := runtimeProbeInput{
		Request:            request,
		SubscriptionDomain: "sync.example.com",
		VPNDomain:          "edge.example.com",
		BotDomain:          "bot.example.com",
		DomainTransaction:  strings.Repeat("a", 64),
	}
	dir := s.path("var/lib/ultra-ingress/upgrade-" + in.DomainTransaction)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	binding := map[string]any{
		"version": 1, "transaction": in.DomainTransaction,
		"evidence": upgradeDomainEvidence{Verified: true},
		"desired": map[string]string{
			"subscription": in.SubscriptionDomain,
			"vpn":          in.VPNDomain,
			"backend":      in.BotDomain,
			"public_host":  in.Request.Bridge.PublicHost,
		},
		"policy": map[string]any{"dns_ttl": 300, "backend_port": 18080, "staging_port": 18443},
	}
	raw, _ := json.Marshal(binding)
	if err := os.WriteFile(filepath.Join(dir, "binding.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if !s.authorizedDomainTransition(in) {
		t.Fatal("exact binding rejected")
	}
	changed := in
	changed.BotDomain = "foreign.example.com"
	if s.authorizedDomainTransition(changed) {
		t.Fatal("backend substitution accepted")
	}
	changed = in
	changed.Request.Bridge.PublicHost = "foreign.example.com"
	if s.authorizedDomainTransition(changed) {
		t.Fatal("dial host substitution accepted")
	}
	changed = in
	changed.DomainTransaction = strings.Repeat("b", 64)
	if s.authorizedDomainTransition(changed) {
		t.Fatal("foreign transaction accepted")
	}
	if err := os.Chmod(filepath.Join(dir, "binding.json"), 0644); err != nil {
		t.Fatal(err)
	}
	if s.authorizedDomainTransition(in) {
		t.Fatal("public binding accepted")
	}
}

func TestUpgradeDomainMigrationIdentityGeneration(t *testing.T) {
	a, b := domainMigrationID("same-domain-1"), domainMigrationID("same-domain-2")
	if len(a) != 36 || a == b || a != domainMigrationID("same-domain-1") {
		t.Fatal("unstable phase identity")
	}
}

func TestRuntimeOnlyDomainConfigSkipsDNSPhases(t *testing.T) {
	transaction := &upgradeDomainTransaction{Changed: true, DNSChanged: false}
	for _, phase := range []string{"prepare", "promote", "retire", "retire-dns", "rollback-dns"} {
		if err := transaction.phase(context.Background(), nil, t.TempDir(), "python3", "missing-ansible", phase, 1); err != nil {
			t.Fatalf("runtime-only %s phase should not call DNS migration: %v", phase, err)
		}
	}
}

func TestUpgradeDomainPolicyRejectsUnsupportedConfigOnlyChanges(t *testing.T) {
	ingress := &installplan.AutomationIngress{Path: "/connect", BackendPort: 18080, GatewayPort: 18081}
	dns := &installplan.AutomationDNS{TTL: 300}
	automation := &installplan.AutomationConfig{BridgeIPv4: "192.0.2.1"}
	base := upgradeDomainEvidence{DNSTTL: 300, ACMEEmailMatches: true, IngressModeMatches: true,
		ForwardHostMatches: true, StagingPortMatches: true, StatusPortMatches: true,
		ExperimentalPortMatch: true, AgeRecipientMatches: true, BridgeProviderMatches: true,
		StaticNodesMatch: true, AdminIDMatches: true, StatePathsMatch: true, ArtifactPathsMatch: true,
		BridgeIPv4: "192.0.2.1", Path: "/connect", BackendPort: 18080, GatewayPort: 18081, Fingerprint: "firefox"}
	if err := validateUpgradeDomainPolicy(base, ingress, dns, automation); err != nil {
		t.Fatalf("unchanged policy rejected: %v", err)
	}
	legacy := base
	legacy.StagingPortMatches = false
	legacy.StagingPortUnrecorded = true
	if err := validateUpgradeDomainPolicy(legacy, ingress, dns, automation); err != nil {
		t.Fatalf("unrecorded ephemeral staging port rejected: %v", err)
	}
	legacy.StagingPortMatches = true
	if err := validateUpgradeDomainPolicy(legacy, ingress, dns, automation); err == nil {
		t.Fatal("contradictory staging-port evidence accepted")
	}
	cases := []struct {
		name string
		edit func(*upgradeDomainEvidence, *installplan.AutomationIngress, *installplan.AutomationDNS, *installplan.AutomationConfig)
		want string
	}{
		{
			"dns ttl",
			func(_ *upgradeDomainEvidence, _ *installplan.AutomationIngress, d *installplan.AutomationDNS, _ *installplan.AutomationConfig) {
				d.TTL = 600
			},
			"upgrade_domain_dns_ttl_migration_required",
		},
		{
			"acme email",
			func(e *upgradeDomainEvidence, _ *installplan.AutomationIngress, _ *installplan.AutomationDNS, _ *installplan.AutomationConfig) {
				e.ACMEEmailMatches = false
			},
			"upgrade_domain_acme_email_migration_required",
		},
		{
			"ingress mode",
			func(e *upgradeDomainEvidence, _ *installplan.AutomationIngress, _ *installplan.AutomationDNS, _ *installplan.AutomationConfig) {
				e.IngressModeMatches = false
			},
			"upgrade_domain_ingress_mode_migration_required",
		},
		{
			"forward host",
			func(e *upgradeDomainEvidence, _ *installplan.AutomationIngress, _ *installplan.AutomationDNS, _ *installplan.AutomationConfig) {
				e.ForwardHostMatches = false
			},
			"upgrade_domain_ingress_mode_migration_required",
		},
		{
			"ingress port policy",
			func(e *upgradeDomainEvidence, _ *installplan.AutomationIngress, _ *installplan.AutomationDNS, _ *installplan.AutomationConfig) {
				e.StagingPortMatches = false
			},
			"upgrade_domain_ingress_ports_migration_required",
		},
		{
			"recovery recipient",
			func(e *upgradeDomainEvidence, _ *installplan.AutomationIngress, _ *installplan.AutomationDNS, _ *installplan.AutomationConfig) {
				e.AgeRecipientMatches = false
			},
			"upgrade_domain_recovery_key_rotation_required",
		},
		{
			"automation topology",
			func(e *upgradeDomainEvidence, _ *installplan.AutomationIngress, _ *installplan.AutomationDNS, _ *installplan.AutomationConfig) {
				e.StaticNodesMatch = false
			},
			"upgrade_domain_automation_topology_migration_required",
		},
		{
			"admin identity",
			func(e *upgradeDomainEvidence, _ *installplan.AutomationIngress, _ *installplan.AutomationDNS, _ *installplan.AutomationConfig) {
				e.AdminIDMatches = false
			},
			"upgrade_domain_admin_identity_migration_required",
		},
		{
			"bridge address",
			func(_ *upgradeDomainEvidence, _ *installplan.AutomationIngress, _ *installplan.AutomationDNS, a *installplan.AutomationConfig) {
				a.BridgeIPv4 = "192.0.2.2"
			},
			"upgrade_domain_bridge_address_migration_required",
		},
		{
			"transport port",
			func(_ *upgradeDomainEvidence, i *installplan.AutomationIngress, _ *installplan.AutomationDNS, _ *installplan.AutomationConfig) {
				i.BackendPort = 19080
			},
			"upgrade_domain_transport_migration_required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := base
			i := *ingress
			d := *dns
			a := *automation
			tc.edit(&e, &i, &d, &a)
			if err := validateUpgradeDomainPolicy(e, &i, &d, &a); err == nil || err.Error() != tc.want {
				t.Fatalf("error = %v, want %s", err, tc.want)
			}
		})
	}
}

func TestUpgradeDomainPolicyRemovalRequiresMigration(t *testing.T) {
	if err := validateUpgradeDomainConfigPresence(&installplan.InstallPlan{Automation: &installplan.AutomationConfig{}}); err == nil ||
		err.Error() != "upgrade_domain_policy_removal_migration_required" {
		t.Fatalf("missing managed DNS/ingress policy accepted: %v", err)
	}
	if err := validateUpgradeDomainConfigPresence(&installplan.InstallPlan{}); err != nil {
		t.Fatalf("legacy plan should retain legacy behavior: %v", err)
	}
}

func TestUpgradeBackupPathDeltaSchedulesRecoveryPolicyCommit(t *testing.T) {
	if upgradeBackupPathsChanged(upgradeDomainEvidence{StatePathsMatch: true, ArtifactPathsMatch: true}) {
		t.Fatal("already covered backup paths should not require a policy commit")
	}
	if !upgradeBackupPathsChanged(upgradeDomainEvidence{StatePathsMatch: false, ArtifactPathsMatch: true}) {
		t.Fatal("newly requested state paths should schedule recovery policy commit")
	}
	if !upgradeBackupPathsChanged(upgradeDomainEvidence{StatePathsMatch: true, ArtifactPathsMatch: false}) {
		t.Fatal("newly requested artifact paths should schedule recovery policy commit")
	}
}

func TestUpgradePublicHostChangeMustBeResolvableByManagedVPNOrBridgeIP(t *testing.T) {
	for _, tc := range []struct{ previous, desired, vpn, bridge, wantErr string }{
		{"old.example.com", "edge.example.com", "edge.example.com", "192.0.2.1", ""},
		{"192.0.2.2", "192.0.2.1", "edge.example.com", "192.0.2.1", ""},
		{"old.example.com", "new.example.net", "edge.example.com", "192.0.2.1", "upgrade_domain_public_host_migration_required"},
	} {
		if err := validateUpgradePublicHostChange(tc.previous, tc.desired, tc.vpn, tc.bridge); (err == nil && tc.wantErr != "") ||
			(err != nil && err.Error() != tc.wantErr) {
			t.Fatalf("host change %q -> %q error=%v want=%q", tc.previous, tc.desired, err, tc.wantErr)
		}
	}
}

func TestUpgradeDomainPreactivationRetryCreatesFreshCandidate(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	root := t.TempDir()
	directory := filepath.Join(root, "upgrade")
	lock := filepath.Join(root, "lock")
	for _, path := range []string{directory, lock} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(root, "ansible")
	script := "#!" + python + "\n" + `import json,pathlib,sys
job=pathlib.Path(sys.argv[-1][1:]).parent
request=json.loads((job/'request.json').read_text())
action=request['variables']['ultra_dns_migration_action']
result={'verified':True,'phase':{'prepare':'prepared','rollback':'rolled_back'}[action]}
(job/'result.json').write_text(json.dumps(result))
(job/'result.json').chmod(0o600)
`
	if err := os.WriteFile(executable, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, release, err := deployansible.WithOperationLock(context.Background(), lock)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	transaction := &upgradeDomainTransaction{
		Changed:    true,
		DNSChanged: true,
		Variables:  map[string]any{"ultra_lock_directory": lock},
		Desired: map[string]any{
			"subscription": map[string]string{"name": "sync", "data": "192.0.2.1"},
			"vpn":          map[string]string{"name": "edge", "data": "192.0.2.1"},
		},
	}
	inventory := map[string]any{"all": map[string]any{"hosts": map[string]any{"bridge": map[string]any{"ansible_host": "192.0.2.1"}}}}
	for _, phase := range []string{"prepare", "rollback-dns", "prepare"} {
		if err := transaction.phase(ctx, inventory, directory, python, executable, phase, 1); err != nil {
			t.Fatalf("%s: %v", phase, err)
		}
	}
	if transaction.Attempt != 2 {
		t.Fatal("compensated domain attempt reused")
	}
	for _, stage := range []string{"domain-prepare", "domain-rollback-dns", "domain-prepare-attempt-2"} {
		if _, err := os.Stat(filepath.Join(directory, stage, "receipt.json")); err != nil {
			t.Fatal("missing exact retry receipt", err)
		}
	}
	first, _ := os.ReadFile(filepath.Join(directory, "domain-prepare", "request.json"))
	second, _ := os.ReadFile(filepath.Join(directory, "domain-prepare-attempt-2", "request.json"))
	dnsSource, err := recoveryassets.Scripts.ReadFile("dns.py")
	if err != nil {
		t.Fatal(err)
	}
	var a, b struct {
		Variables map[string]any `json:"variables"`
	}
	if json.Unmarshal(first, &a) != nil || json.Unmarshal(second, &b) != nil ||
		a.Variables["ultra_dns_migration_operation_id"] == b.Variables["ultra_dns_migration_operation_id"] {
		t.Fatal("fresh candidate reused provider operation identity")
	}
	if a.Variables["ultra_dns_migration_application_source"] != string(dnsSource) ||
		b.Variables["ultra_dns_migration_application_source"] != string(dnsSource) {
		t.Fatal("DNS helper source was not supplied from the trusted embedded bundle")
	}
}
