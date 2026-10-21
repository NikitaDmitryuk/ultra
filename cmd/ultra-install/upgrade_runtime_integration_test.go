package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestRuntimeTransportRequestBoundReplayAndExactRollback(t *testing.T) {
	s, request := runtimeHostFixture(t)
	// Establish a matching tunable runtime, then change a setting requiring no
	// external firewall/TLS/service provisioning. Credentials remain host-local.
	request.Bridge.PublicHost = "vpn.example.com"
	request.Features.LogLevel = "info"
	if _, err := s.prepare(request); err != nil {
		t.Fatal(err)
	}
	if _, err := s.transition(request.Transaction, false); err != nil {
		t.Fatal(err)
	}
	path, _ := s.journalPath(request.Transaction)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	before := []runtimeHostImage{}
	for _, file := range runtimeHostFiles {
		image, err := s.image(s.path(file))
		if err != nil {
			t.Fatal(err)
		}
		before = append(before, image)
	}
	request.Features.DomainDirect = "example.net"
	in := runtimeProbeInput{Request: request, BotActive: true, Action: "prepare"}
	probe, err := inspectRuntimeHost(s, in)
	if err != nil || !probe.RuntimeChanged || probe.DomainChanged || len(probe.Transitions) != 0 {
		t.Fatalf("probe: %+v %v", probe, err)
	}
	for i := 0; i < 2; i++ {
		result, err := runtimeHostTransport(s, in)
		if err != nil || result.Status != "prepared" || !result.BotActive {
			t.Fatalf("prepare replay: %+v %v", result, err)
		}
	}
	changed := in
	changed.Request.Features.DomainDirect = "other.example.net"
	if _, err = runtimeHostTransport(s, changed); err == nil {
		t.Fatal("different request resumed a host transaction")
	}
	in.Action, in.BotActive = "apply", false
	result, err := runtimeHostTransport(s, in)
	if err != nil || result.Status != "applied" || !result.BotActive {
		t.Fatalf("apply lost original service state: %+v %v", result, err)
	}
	if _, err = runtimeHostTransport(s, in); err != nil {
		t.Fatal("idempotent apply", err)
	}
	in.Action = "rollback"
	if _, err = runtimeHostTransport(s, in); err != nil {
		t.Fatal(err)
	}
	if _, err = runtimeHostTransport(s, in); err != nil {
		t.Fatal("idempotent rollback", err)
	}
	for i, file := range runtimeHostFiles {
		after, err := s.image(s.path(file))
		if err != nil || !runtimeHostImagesEqual(before[i], after) {
			t.Fatal("rollback changed exact prior image", err)
		}
	}
	in.Action = "apply"
	if _, err = runtimeHostTransport(s, in); err == nil {
		t.Fatal("finished transaction reapplied")
	}
}

func TestRuntimeProbeStrictRequestAndWhitelistedResult(t *testing.T) {
	s, request := runtimeHostFixture(t)
	in := runtimeProbeInput{Request: request}
	raw, _ := json.Marshal(in)
	for _, invalid := range [][]byte{append(raw, []byte(" {}")...), []byte(`{"remote_path":"/tmp/spec"}`), []byte(strings.Repeat(" ", 65537))} {
		if _, err := decodeRuntimeProbe(bytes.NewReader(invalid), s); err == nil {
			t.Fatal("untrusted request accepted")
		}
	}
	result, _ := json.Marshal(runtimeProbeResult{Verified: true, RuntimeChanged: true})
	for _, forbidden := range []string{"secret", "spec", "environment", "tunnel_uuid", "DSN"} {
		if bytes.Contains(result, []byte(forbidden)) {
			t.Fatal("result exposed private input")
		}
	}
}

func TestRuntimeRollbackWithoutPreparedJournalDoesNotAuthorizeServiceMutation(t *testing.T) {
	s, request := runtimeHostFixture(t)
	in := runtimeProbeInput{Request: request, Action: "status", BotActive: true}
	status, err := runtimeHostTransport(s, in)
	if err != nil || !status.Verified || status.Bound {
		t.Fatalf("unprepared transaction authorized service changes: %+v %v", status, err)
	}
	in.Action = "rollback"
	result, err := runtimeHostTransport(s, in)
	if err != nil || !result.Verified || result.Bound || result.Status != "rolled_back" {
		t.Fatalf("rollback touched unprepared transaction: %+v %v", result, err)
	}
	if err = os.Remove(s.path(runtimeHostStateDir)); err != nil {
		t.Fatal(err)
	}
	result, err = runtimeHostTransport(s, in)
	if err != nil || result.Bound {
		t.Fatal("absent journal directory authorized changes", err)
	}
}

func TestUpgradeRuntimeEvidenceAllowsOrdinaryChangesAndRejectsSpecificProvisioning(t *testing.T) {
	requests := map[string]any{"bridge": runtimeProbeInput{}}
	evidence := runtimeProbeResult{Verified: true, RuntimeChanged: true}
	values := map[string]any{"verified": true, "hosts": map[string]runtimeProbeResult{"bridge": evidence}}
	if err := validateUpgradeRuntimeEvidence(values, requests); err != nil {
		t.Fatal("ordinary canonical changes must apply", err)
	}
	for transition, code := range map[installplan.RuntimeTransitionKind]string{
		installplan.RuntimeTransitionTLS: "effect_checkpoint", installplan.RuntimeTransitionWARP: "effect_checkpoint",
		installplan.RuntimeTransitionListener: "effect_checkpoint", installplan.RuntimeTransitionTunnel: "effect_checkpoint",
	} {
		evidence.Transitions = []installplan.RuntimeTransitionKind{transition}
		values["hosts"] = map[string]runtimeProbeResult{"bridge": evidence}
		if err := validateUpgradeRuntimeEvidence(values, requests); err == nil || !strings.Contains(err.Error(), code) {
			t.Fatalf("%s lacks dependency guard: %v", transition, err)
		}
		evidence.EffectsReady = true
		values["hosts"] = map[string]runtimeProbeResult{"bridge": evidence}
		if err := validateUpgradeRuntimeEvidence(values, requests); err != nil {
			t.Fatal("verified dependency evidence rejected", err)
		}
		evidence.EffectsReady = false
	}
	if validateUpgradeRuntimeEvidence(values, map[string]any{"missing": nil}) == nil {
		t.Fatal("missing host accepted")
	}
}

func TestUpgradeRuntimeProofBoundToStaticAndDynamicFrozenTargets(t *testing.T) {
	s, request := runtimeHostFixture(t)
	_ = s
	plan := &installplan.InstallPlan{
		SourceValues: map[string]string{},
		Bridge:       request.Bridge,
		Database:     request.Database,
		Features:     request.Features,
	}
	plan.Exits = []installplan.ExitNode{{Name: "primary", SSHHost: "192.0.2.2", DialAddr: "192.0.2.2", Port: 9443}}
	var inspection upgradeInspection
	raw := `{"observed_at":1,"topology_sha256":"` + strings.Repeat(
		"a",
		64,
	) + `","identity":"fixture","nodes":[{"id":"11111111-1111-1111-1111-111111111111","address":"192.0.2.2","pins":"fixture-pin"},{"id":"22222222-2222-2222-2222-222222222222","address":"192.0.2.3","pins":"fixture-pin"}],"runtime_nodes":{"11111111-1111-1111-1111-111111111111":{"name":"primary","managed":false,"tunnel_identity_digest":"` + strings.Repeat(
		"b",
		64,
	) + `"},"22222222-2222-2222-2222-222222222222":{"name":"dynamic","managed":true,"tunnel_identity_digest":"` + strings.Repeat(
		"c",
		64,
	) + `"}}}`
	if json.Unmarshal([]byte(raw), &inspection) != nil {
		t.Fatal("fixture")
	}
	nodes, err := freezeUpgradeExits(inspection, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	inventory := map[string]any{"all": map[string]any{"children": map[string]any{"exits": map[string]any{"hosts": nodes}}}}
	requests, err := upgradeRuntimeRequests(plan, inspection, inventory, "fixture-runtime-1")
	if err != nil || len(requests) != 3 {
		t.Fatalf("requests: %v", err)
	}
	dynamic := requests["exit_22222222222222222222222222222222"].(runtimeProbeInput).Request
	if dynamic.Node != "" || dynamic.Proof.NodeID == "" || dynamic.Proof.TopologySHA != inspection.TopologySHA {
		t.Fatal("dynamic proof not bound")
	}
	identity, err := runtimeHostDesiredIdentity(dynamic)
	if err != nil || identity != dynamic.Proof.DesiredIdentity {
		t.Fatal("dynamic desired identity invalid", err)
	}
	dynamic.Proof.SSHHost = "192.0.2.9"
	other, _ := runtimeHostDesiredIdentity(dynamic)
	if other == identity {
		t.Fatal("dynamic identity ignored target address")
	}
	plan.Features.MainExitDomain = "tunnel.example.com"
	evidence := inspection.RuntimeNodes["22222222-2222-2222-2222-222222222222"]
	evidence.CertificatePin = strings.Repeat("d", 64)
	inspection.RuntimeNodes["22222222-2222-2222-2222-222222222222"] = evidence
	requests, err = upgradeRuntimeRequests(plan, inspection, inventory, "fixture-runtime-1")
	if err != nil {
		t.Fatal("mixed ACME and managed pinned fleet rejected", err)
	}
	dynamic = requests["exit_22222222222222222222222222222222"].(runtimeProbeInput).Request
	static := requests["exit_11111111111111111111111111111111"].(runtimeProbeInput).Request
	bridge := requests["bridge"].(runtimeProbeInput).Request
	if dynamic.Features.MainExitDomain != "" || !dynamic.Features.GenerateExitTLS ||
		dynamic.Proof.CertificatePin != evidence.CertificatePin ||
		static.Features.MainExitDomain != plan.Features.MainExitDomain ||
		bridge.Features.MainExitDomain != plan.Features.MainExitDomain {
		t.Fatal("per-node TLS policy or certificate proof lost")
	}
	variables := map[string]any{}
	if err := attachManagedTunnelVariables(plan, requests, variables, map[string]any{"ultra_release_manifest": map[string]any{}}, t.TempDir(), 1); err != nil {
		t.Fatal(err)
	}
	fences := variables["ultra_managed_tunnel_requests"].(map[string]string)
	if len(fences) != 1 || fences["exit_11111111111111111111111111111111"] == "" {
		t.Fatal("ACME fence applied to managed IP exit")
	}
	for _, field := range []string{"unowned", "missing pin", "malformed pin", "managed static", "multiple static"} {
		t.Run(field, func(t *testing.T) {
			copyPlan := *plan
			copyInspection := inspection
			copyInspection.RuntimeNodes = map[string]upgradeRuntimeNodeEvidence{}
			for id, item := range inspection.RuntimeNodes {
				copyInspection.RuntimeNodes[id] = item
			}
			bad := evidence
			switch field {
			case "unowned":
				bad.Managed = false
			case "missing pin":
				bad.CertificatePin = ""
			case "malformed pin":
				bad.CertificatePin = "abcd"
			case "managed static":
				item := copyInspection.RuntimeNodes["11111111-1111-1111-1111-111111111111"]
				item.Managed = true
				copyInspection.RuntimeNodes["11111111-1111-1111-1111-111111111111"] = item
			case "multiple static":
				copyPlan.Exits = append(append([]installplan.ExitNode{}, plan.Exits...), installplan.ExitNode{Name: "second"})
			}
			copyInspection.RuntimeNodes["22222222-2222-2222-2222-222222222222"] = bad
			if _, err := upgradeRuntimeRequests(&copyPlan, copyInspection, inventory, "fixture-runtime-1"); err == nil {
				t.Fatal("unproven fleet accepted")
			}
		})
	}
	nodes["exit_22222222222222222222222222222222"].(map[string]any)["ansible_host"] = "192.0.2.9"
	if _, err = upgradeRuntimeRequests(plan, inspection, inventory, "fixture-runtime-1"); err == nil {
		t.Fatal("changed SSH target accepted")
	}
}

func TestUpgradeRuntimeStaticExitsRequiresCanonicalSourceEvidence(t *testing.T) {
	p := &installplan.InstallPlan{
		SourceValues: map[string]string{"BRIDGE_IP": "192.0.2.1", "MAIN_EXIT_IP": "192.0.2.2"},
		Exits:        []installplan.ExitNode{{Name: "primary", SSHHost: "192.0.2.2", DialAddr: "192.0.2.2", Port: 9443}},
		Automation: &installplan.AutomationConfig{
			StaticNodes: []installplan.AutomationNode{{Name: "NL", Address: "192.0.2.2", Provider: "fixture"}},
		},
	}
	exits, err := upgradeRuntimeStaticExits(p)
	if err != nil || len(exits) != 1 || exits[0] != p.Exits[0] {
		t.Fatalf("legacy/internal plan lost explicit exits: %+v %v", exits, err)
	}
	p.SourceValues["INSTALL_SCHEMA_VERSION"] = "2"
	if _, err := upgradeRuntimeStaticExits(p); err == nil {
		t.Fatal("declared canonical config accepted missing static policy")
	}
	delete(p.SourceValues, "INSTALL_SCHEMA_VERSION")
	p.SourceValues["ULTRA_AUTOMATION_STATIC_NODES"] = ""
	if _, err := upgradeRuntimeStaticExits(p); err == nil {
		t.Fatal("explicit invalid static policy fell back to legacy exits")
	}
}

func TestUpgradeRuntimeCanonicalSyntheticStaticTopology(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python unavailable")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "upgrade-install.config")
	// Exercise the actual config writer and canonical file parser with a separate
	// direct-ingress preflight fixture. Ordinary isolated VMs use forward ingress
	// without managed DNS and cannot perform the signed serial upgrade yet.
	script := `import json,pathlib,sys
root=pathlib.Path(sys.argv[1])
sys.path.insert(0,str(root/'deploy/recovery'))
import vm_acceptance
plan=json.loads((root/'deploy/install-plan-v2.example.json').read_text())
plan['bot'].update(domain='vpn.fixture.test',subscription_domain='sync.fixture.test')
plan['automation']['dns']={'provider':'vultr','zone':'fixture.test','ttl':300,'subscription_name':'sync','vpn_name':'vpn'}
plan['automation']['ingress'].update(domain='vpn.fixture.test',forward_host='')
env=pathlib.Path(sys.argv[2]).with_name('synthetic.env')
env.write_text('ULTRA_VULTR_API_KEY=synthetic-no-provider-permission\nTELEGRAM_BOT_TOKEN=fixture-token\n')
env.chmod(0o600)
plan['secrets']['env_file']=str(env)
plan['exits']=[{'name':'NL','ssh_host':'192.0.2.20','priority':100},{'name':'US','ssh_host':'192.0.2.30','priority':200}]
plan['automation']['static_nodes']=[{'name':e['name'],'address':e['ssh_host'],'provider':'fixture-'+e['name'],'budget':{'monthly_bytes':1048576,'is_fallback':i==0}} for i,e in enumerate(plan['exits'])]
pathlib.Path(sys.argv[2]).write_text(vm_acceptance.synthetic_upgrade_config(plan,{'version':'v2.3.2','directory':'/fixture/release'},'fixture-public-key'))
`
	if out, err := exec.Command(python, "-c", script, root, path).CombinedOutput(); err != nil {
		t.Fatalf("synthetic config: %v: %s", err, out)
	}
	load := func(t *testing.T) *installplan.InstallPlan {
		t.Helper()
		p, err := installplan.LoadLifecycleConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := load(t)
	if err := installplan.ValidatePlan(p); err != nil {
		t.Fatalf("synthetic canonical plan validation: %v", err)
	}
	if err := validateUpgradeDomainConfigPresence(p); err != nil {
		t.Fatalf("synthetic canonical domain preflight: %v", err)
	}
	// Ingress bootstrap unconditionally runs this preparation for prepare,
	// activate, stage and rollback. Validate that actual local prerequisite,
	// including the shared provider credential, without running its Ansible role.
	dnsVariables := map[string]any{}
	if err := prepareAnsibleDNS(p, dnsVariables); err != nil {
		t.Fatalf("direct synthetic bootstrap DNS preparation: %v", err)
	}
	if dnsVariables["ultra_dns_api_key"] != "synthetic-no-provider-permission" {
		t.Fatal("synthetic shared DNS credential not projected")
	}
	if _, err := prepareProviderSecrets(p, t.TempDir()); err != nil {
		t.Fatalf("synthetic bootstrap provider preparation: %v", err)
	}
	t.Run("forward DNS bootstrap remains rejected", func(t *testing.T) {
		bad := load(t)
		bad.Automation.Ingress.ForwardHost = "192.0.2.20"
		if err := prepareAnsibleDNS(bad, map[string]any{}); err == nil || err.Error() != "managed DNS requires direct bridge ingress" {
			t.Fatalf("forward DNS bootstrap did not fail closed: %v", err)
		}
	})
	t.Run("missing shared DNS key remains rejected", func(t *testing.T) {
		bad := load(t)
		env := filepath.Join(t.TempDir(), "empty.env")
		if err := os.WriteFile(env, []byte("TELEGRAM_BOT_TOKEN=fixture-token\n"), 0600); err != nil {
			t.Fatal(err)
		}
		bad.Secrets.EnvFile = env
		if err := prepareAnsibleDNS(bad, map[string]any{}); err == nil ||
			err.Error() != "canonical Vultr API key required for managed DNS" {
			t.Fatalf("missing DNS credential did not fail closed: %v", err)
		}
	})
	if dns := p.Automation.DNS; dns.Provider != "vultr" || dns.Zone != "fixture.test" || dns.TTL != 300 ||
		dns.SubscriptionName != "sync" || dns.VPNName != "vpn" || p.PublicSubscriptionDomain() != "sync.fixture.test" {
		t.Fatalf("synthetic canonical DNS policy lost: %+v", dns)
	}
	ingress := p.Automation.Ingress
	// Match a hypothetical installed direct-ingress policy: these pure gates
	// must pass without DNS/provider mutation or a live provider credential.
	evidence := upgradeDomainEvidence{DNSTTL: 300, ACMEEmailMatches: true, IngressModeMatches: true,
		ForwardHostMatches: true, StagingPortMatches: true, StatusPortMatches: true,
		ExperimentalPortMatch: true, AgeRecipientMatches: true, BridgeProviderMatches: true,
		StaticNodesMatch: true, AdminIDMatches: true, StatePathsMatch: true, ArtifactPathsMatch: true,
		BridgeIPv4: p.Automation.BridgeIPv4, Path: ingress.Path, BackendPort: ingress.BackendPort,
		GatewayPort: ingress.GatewayPort, Fingerprint: "firefox"}
	if err := validateUpgradeDomainPolicy(evidence, ingress, p.Automation.DNS, p.Automation); err != nil {
		t.Fatalf("unchanged synthetic domain policy rejected: %v", err)
	}
	t.Run("missing DNS still fails domain preflight", func(t *testing.T) {
		bad := load(t)
		delete(bad.SourceValues, "DNS_PROVIDER")
		withoutDNS, err := installplan.CanonicalLifecycleValuesToPlan(bad.SourceValues)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateUpgradeDomainConfigPresence(withoutDNS); err == nil ||
			err.Error() != "upgrade_domain_policy_removal_migration_required" {
			t.Fatalf("missing DNS did not fail closed: %v", err)
		}
	})
	if len(p.Exits) != 1 || p.Exits[0].Name != "primary" || p.Exits[0].SSHHost != "192.0.2.20" {
		t.Fatal("canonical bootstrap contract changed")
	}
	const nlID = "11111111-1111-1111-1111-111111111111"
	const usID = "22222222-2222-2222-2222-222222222222"
	var inspection upgradeInspection
	if err := json.Unmarshal([]byte(`{"topology_sha256":"`+strings.Repeat("a", 64)+`","nodes":[{"id":"`+nlID+`","address":"192.0.2.20","pins":"fixture-pin"},{"id":"`+usID+`","address":"192.0.2.30","pins":"fixture-pin"}]}`), &inspection); err != nil {
		t.Fatal(err)
	}
	inspection.ObservedAt, inspection.Identity = 1, "fixture-identity"
	inspection.RuntimeNodes = map[string]upgradeRuntimeNodeEvidence{
		nlID: {Name: "NL", TunnelIdentityDigest: strings.Repeat("b", 64)},
		usID: {Name: "US", TunnelIdentityDigest: strings.Repeat("c", 64)},
	}
	nodes, err := freezeUpgradeExits(inspection, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	inventory := map[string]any{
		"all": map[string]any{"children": map[string]any{"exits": map[string]any{"hosts": nodes}}},
	}
	check := func(t *testing.T, p *installplan.InstallPlan) {
		t.Helper()
		requests, err := upgradeRuntimeRequests(p, inspection, inventory, "fixture-runtime-1")
		if err != nil || len(requests) != 3 {
			t.Fatalf("canonical static requests: %v", err)
		}
		bridge := requests["bridge"].(runtimeProbeInput).Request
		if len(bridge.Exits) != 2 || bridge.Exits[0].Name != "NL" || bridge.Exits[1].Name != "US" ||
			bridge.Exits[0].SSHHost != "192.0.2.20" || bridge.Exits[1].DialAddr != "192.0.2.30" {
			t.Fatalf("lost exact main-first runtime topology: %+v", bridge.Exits)
		}
		for id, name := range map[string]string{nlID: "NL", usID: "US"} {
			r := requests["exit_"+strings.ReplaceAll(id, "-", "")].(runtimeProbeInput).Request
			if r.Node != name || r.Proof.Node != name || r.Proof.NodeID != "" ||
				r.Proof.DesiredIdentity == "" {
				t.Fatalf("lost static proof for %s", name)
			}
		}
		if len(p.Exits) != 1 || p.Exits[0].Name != "primary" {
			t.Fatal("request construction mutated canonical bootstrap plan")
		}
	}
	check(t, p)
	// Reordering policy cannot change which address is the main exit.
	v := p.SourceValues
	var policy []installplan.AutomationNode
	if err := json.Unmarshal([]byte(v["ULTRA_AUTOMATION_STATIC_NODES"]), &policy); err != nil {
		t.Fatal(err)
	}
	policy[0], policy[1] = policy[1], policy[0]
	raw, _ := json.Marshal(policy)
	v["ULTRA_AUTOMATION_STATIC_NODES"] = string(raw)
	reordered, err := installplan.CanonicalLifecycleValuesToPlan(v)
	if err != nil {
		t.Fatal(err)
	}
	check(t, reordered)
	t.Run("canonical main with additional managed exit", func(t *testing.T) {
		mixed := load(t)
		mixed.Automation.StaticNodes = mixed.Automation.StaticNodes[:1]
		raw, _ := json.Marshal(mixed.Automation.StaticNodes)
		mixed.SourceValues["ULTRA_AUTOMATION_STATIC_NODES"] = string(raw)
		managedInspection := inspection
		managedInspection.RuntimeNodes = map[string]upgradeRuntimeNodeEvidence{
			nlID: inspection.RuntimeNodes[nlID],
			usID: {Name: "US", Managed: true, TunnelIdentityDigest: strings.Repeat("c", 64)},
		}
		requests, err := upgradeRuntimeRequests(
			mixed,
			managedInspection,
			inventory,
			"fixture-runtime-1",
		)
		if err != nil || len(requests) != 3 {
			t.Fatalf("canonical static and managed fleet: %v", err)
		}
		dynamic := requests["exit_"+strings.ReplaceAll(usID, "-", "")].(runtimeProbeInput).Request
		if dynamic.Node != "" || dynamic.Proof.NodeID != usID ||
			dynamic.Proof.TopologySHA != inspection.TopologySHA {
			t.Fatal("managed exit lost frozen topology proof")
		}
	})
	for _, field := range []string{"missing primary", "mismatched primary", "duplicate name", "duplicate address", "missing node", "renamed node", "policy mismatch", "managed tunnel"} {
		t.Run(field, func(t *testing.T) {
			bad := load(t)
			switch field {
			case "missing primary":
				delete(bad.SourceValues, "MAIN_EXIT_IP")
			case "mismatched primary":
				bad.SourceValues["MAIN_EXIT_IP"] = "192.0.2.99"
				bad.Exits[0].SSHHost, bad.Exits[0].DialAddr = "192.0.2.99", "192.0.2.99"
			case "duplicate name":
				bad.Automation.StaticNodes[1].Name = "NL"
			case "duplicate address":
				bad.Automation.StaticNodes[1].Address = "192.0.2.20"
			case "missing node":
				bad.Automation.StaticNodes = bad.Automation.StaticNodes[:1]
			case "renamed node":
				bad.Automation.StaticNodes[1].Name = "other"
			case "policy mismatch":
				delete(bad.SourceValues, "ULTRA_AUTOMATION_STATIC_NODES")
			case "managed tunnel":
				bad.Features.MainExitDomain = "tunnel.example.com"
			}
			if field != "policy mismatch" {
				raw, _ := json.Marshal(bad.Automation.StaticNodes)
				bad.SourceValues["ULTRA_AUTOMATION_STATIC_NODES"] = string(raw)
			}
			if _, err := upgradeRuntimeRequests(bad, inspection, inventory, "fixture-runtime-1"); err == nil {
				t.Fatal("ambiguous or changed canonical topology accepted")
			}
		})
	}
}

func TestFinalReleaseRollbackRestoresInactiveDisabledBot(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python unavailable")
	}
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(directory, "../.."))
	script := `import importlib.util, pathlib, re, sys, tempfile, types
basic=types.ModuleType('ansible.module_utils.basic')
basic.AnsibleModule=object
sys.modules['ansible']=types.ModuleType('ansible')
sys.modules['ansible.module_utils']=types.ModuleType('ansible.module_utils')
sys.modules['ansible.module_utils.basic']=basic
root=pathlib.Path(sys.argv[1])
spec=importlib.util.spec_from_file_location('fixture',root/'scripts/test-ansible-runtime-effects.py')
fixture=importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
playbook=(root/'deploy/ansible/playbooks/rollback.yml').read_text()
final=playbook[playbook.index('    - name: Read the exact runtime effect rollback binding'):playbook.index('    - name: Save the verified operation result')]
actions=re.findall(r'        action: ([a-z-]+)',final)
assert actions==['status','rollback','accept-rollback'],actions
for failure in ('activation','commit'):
    with tempfile.TemporaryDirectory() as tmp:
        _,host,operation,request=fixture.RuntimeEffectsTests().fixture(tmp)
        host.bot={'active':'inactive','enabled':'disabled'}
        original=dict(host.bot)
        plan={'role':'bridge','classes':['listener'],'ports':[],'tls':False,'bot_service':True,'bot_enabled':True}
        operation.prepare(request,plan,{})
        if failure=='commit':
            operation.transition(request,plan,{},'apply')
            operation.transition(request,plan,{},'accept')
        operation.transition(request,plan,{},'rollback')
        operation.transition(request,plan,{},'accept-rollback')
        host.bot['active']='active' # Binary release rollback restarts the restored bot.
        for action in actions:
            operation.transition(request,{}, {}, action)
        assert host.bot==original,(failure,host.bot)
`
	command := exec.Command(python, "-c", script, root)
	command.Env = []string{"PATH=/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE=1"}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("synthetic final service restoration: %v\n%s", err, output)
	}
}

func TestDomainCompensationReplayUsesExactAttemptReceipts(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python unavailable")
	}
	for _, action := range []string{"apply", "accept", "rollback", "rollback-dns"} {
		t.Run(action, func(t *testing.T) {
			root := t.TempDir()
			directory, lock := filepath.Join(root, "upgrade"), filepath.Join(root, "lock")
			for _, path := range []string{directory, lock} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			ctx, unlock, err := deployansible.WithOperationLock(context.Background(), lock)
			if err != nil {
				t.Fatal(err)
			}
			defer unlock()
			probe := filepath.Join(root, "probe")
			if err := os.WriteFile(probe, []byte("https://old.example.com/sub/test-token\n"), 0600); err != nil {
				t.Fatal(err)
			}
			executable := filepath.Join(root, "ansible")
			script := "#!" + python + "\n" + `import json,pathlib,sys
job=pathlib.Path(sys.argv[-1][1:]).parent
count=job/'calls'
n=int(count.read_text())+1 if count.exists() else 1
count.write_text(str(n))
if n==1:sys.exit(1)
variables=json.loads((job/'request.json').read_text())['variables']
action=variables.get('ultra_upgrade_domain_action')
if not action:action={'rollback':'rolled_back'}[variables['ultra_dns_migration_action']]
result=job/'result.json'
result.write_text(json.dumps({'verified':True,'phase':action}))
result.chmod(0o600)
`
			if err := os.WriteFile(executable, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			marker, _ := json.Marshal(map[string]int{"version": 1, "generation": 3, "attempt": 2})
			if err := os.WriteFile(filepath.Join(directory, "domain-generation-3.json"), marker, 0600); err != nil {
				t.Fatal(err)
			}
			transaction := &upgradeDomainTransaction{
				Changed:        true,
				DNSChanged:     true,
				BackendChanged: true,
				ProbeFile:      probe,
				Evidence:       upgradeDomainEvidence{Subscription: "old.example.com"},
				Variables:      map[string]any{"ultra_lock_directory": lock, "ultra_subscription_domain": "new.example.com"},
				Desired:        map[string]any{"subscription": map[string]string{"name": "new", "data": "192.0.2.1"}},
			}
			inventory := map[string]any{}
			if err := transaction.phase(ctx, inventory, directory, python, executable, action, 3); err == nil {
				t.Fatal("initial failure missing")
			}
			if err := requireFailedUpgradeAttempt(directory, 3); err != nil {
				t.Fatal("exact domain failure not recognized", err)
			}
			stage := upgradeDependentStageDirectory(directory, fmt.Sprintf("domain-%s-attempt-2", action), 3)
			original, err := os.ReadFile(filepath.Join(stage, "request.json"))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(original, []byte("test-token")) || bytes.Contains(original, []byte("ultra_cutover_subscription_url\"")) {
				t.Fatal("credential persisted in immutable request")
			}
			if action == "apply" || action == "accept" {
				var saved struct {
					Variables map[string]any `json:"variables"`
				}
				if err := json.Unmarshal(original, &saved); err != nil {
					t.Fatal(err)
				}
				if saved.Variables["ultra_cutover_subscription_url_file"] != probe ||
					saved.Variables["ultra_cutover_subscription_url_sha256"] != transaction.ProbeSHA256 ||
					saved.Variables["ultra_cutover_subscription_source_domain"] != "old.example.com" ||
					saved.Variables["ultra_subscription_domain"] != "new.example.com" {
					t.Fatal("request does not bind observed probe host separately from acceptance target")
				}
			}
			for _, name := range []string{"variables.json", "bundle/vars.yml"} {
				raw, err := os.ReadFile(filepath.Join(stage, name))
				if err == nil && bytes.Contains(raw, []byte("test-token")) {
					t.Fatalf("credential persisted in %s", name)
				}
			}
			for range 2 {
				if err := transaction.phase(ctx, inventory, directory, python, executable, action, 3); err != nil {
					t.Fatal(err)
				}
			}
			// Successful stage replay uses the bound path/digest request and its
			// verified receipt after terminal manual-deploy cleanup removes the URL.
			if err := os.Remove(probe); err != nil {
				t.Fatal(err)
			}
			transaction.ProbeSHA256 = "" // Reload the durable binding after restart.
			if err := transaction.phase(ctx, inventory, directory, python, executable, action, 3); err != nil {
				t.Fatal("completed replay requires deleted credential", err)
			}
			after, err := os.ReadFile(filepath.Join(stage, "request.json"))
			if err != nil || !bytes.Equal(original, after) {
				t.Fatal("request changed", err)
			}
			count, _ := os.ReadFile(filepath.Join(stage, "calls"))
			if string(count) != "2" {
				t.Fatalf("compensation executions: %s", count)
			}
			if _, err := os.Stat(filepath.Join(stage, "history", "attempt-1.json")); err != nil {
				t.Fatal("original failed receipt lost", err)
			}
			if transaction.Attempt != 2 {
				t.Fatal("compensation changed domain attempt")
			}
		})
	}
}
