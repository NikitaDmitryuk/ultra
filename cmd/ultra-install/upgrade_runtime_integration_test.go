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
	nodes["exit_22222222222222222222222222222222"].(map[string]any)["ansible_host"] = "192.0.2.9"
	if _, err = upgradeRuntimeRequests(plan, inspection, inventory, "fixture-runtime-1"); err == nil {
		t.Fatal("changed SSH target accepted")
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
