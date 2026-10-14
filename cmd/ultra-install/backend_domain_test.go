package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func backendTestPlan() *installplan.InstallPlan {
	return &installplan.InstallPlan{
		Bridge:     installplan.BridgeConfig{SSHHost: "192.0.2.1", Address: "192.0.2.1"},
		Bot:        installplan.BotConfig{Domain: "old.example.com", SubscriptionDomain: "sync.example.com"},
		Automation: &installplan.AutomationConfig{Ingress: &installplan.AutomationIngress{Domain: "edge.example.com"}, DNS: &installplan.AutomationDNS{Zone: "example.com"}},
	}
}

func TestBackendDomainPolicyPreservesPublicNames(t *testing.T) {
	p := backendTestPlan()
	values, err := backendDomainPolicy(p, "core.example.com", "example.com", "apply", "", "/tmp/pins", "ops@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if values["ultra_subscription_domain"] != "sync.example.com" || values["ultra_backend_vpn_domain"] != "edge.example.com" || p.Bot.Domain != "old.example.com" {
		t.Fatal("public or canonical identity changed")
	}
	accept, err := backendDomainPolicy(p, "core.example.com", "example.com", "accept", "", "/tmp/pins", "ops@example.com")
	if err != nil || values["ultra_backend_transaction"] != accept["ultra_backend_transaction"] {
		t.Fatal("acceptance must reverify same transaction")
	}
}

func TestBackendDomainPolicyRejectsUnsafeInputs(t *testing.T) {
	for _, domain := range []string{"sync.example.com", "edge.example.com", "old.example.com", "example.com", "core.other.net", "a.b.example.com", "core.example.com;bad", "CORE.example.com"} {
		if _, err := backendDomainPolicy(backendTestPlan(), domain, "example.com", "apply", "", "/tmp/pins", "ops@example.com"); err == nil {
			t.Fatalf("accepted %q", domain)
		}
	}
	p := backendTestPlan()
	p.Automation = nil
	if _, err := backendDomainPolicy(p, "core.example.com", "example.com", "apply", "", "/tmp/pins", "ops@example.com"); err == nil {
		t.Fatal("unmanaged deployment accepted")
	}
}

func TestBackendDomainRollbackAfterAcceptanceKeepsOriginalTransaction(t *testing.T) {
	p := backendTestPlan()
	before, err := backendDomainPolicy(p, "core.example.com", "example.com", "apply", "", "/tmp/pins", "ops@example.com")
	if err != nil {
		t.Fatal(err)
	}
	p.Bot.Domain = "core.example.com"
	after, err := backendDomainPolicy(p, "core.example.com", "example.com", "accept-rollback", "old.example.com", "/tmp/pins", "ops@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if before["ultra_backend_transaction"] != after["ultra_backend_transaction"] || !strings.HasPrefix(after["ultra_backend_transaction"].(string), "/var/lib/ultra-ingress/backend-") {
		t.Fatal("rollback lost original transaction")
	}
}

// Exercise the real local controller and immutable receipts; only Ansible's
// remote execution is replaced. No SSH or deployed state is accessed.
func backendOperationFixture(t *testing.T) (string, func(string) error) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python unavailable")
	}
	root := t.TempDir()
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	pins := filepath.Join(root, "pins")
	if err = os.WriteFile(pins, []byte("fixture pins"), 0600); err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(root, "ansible-playbook")
	source := "#!" + python + `
import json,pathlib,subprocess,sys
root=pathlib.Path(__file__).parent
variables=json.loads((pathlib.Path(sys.argv[-1][1:]).parent/'variables.json').read_text())
job=pathlib.Path(variables['ultra_result_file']).parent
operation=json.loads((job/'job.json').read_text())['operation']
action=variables.get('ultra_backend_action',variables.get('ultra_lifecycle_phase',''))
with (root/'operations').open('a') as stream:
 stream.write(json.dumps({'action':action,'id':variables.get('ultra_lifecycle_id'),'job':str(job),'transaction':variables.get('ultra_backend_transaction')})+'\n')
if (root/('fail-'+action)).exists():sys.exit(1)
if action=='rollback' and (root/'recover-pre-state.py').exists():
 subprocess.run([sys.executable,str(root/'recover-pre-state.py')],check=True)
result=pathlib.Path(variables['ultra_result_file'])
result.write_text(json.dumps({'verified':not (root/('unverified-'+action)).exists()}));result.chmod(0o600)
`
	if err = os.WriteFile(stub, []byte(source), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ULTRA_INSTALL_STATE_DIR", filepath.Join(root, "state"))
	t.Setenv("ULTRA_ANSIBLE_EXECUTABLE", stub)
	// applyBackendDomain sets this variable as part of the real invocation.
	t.Setenv("ULTRA_INSTALL_SSH_KNOWN_HOSTS", pins)
	config := filepath.Join(root, "install.config")
	if err = os.WriteFile(config, []byte("BOT_DOMAIN=old.example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return root, func(action string) error {
		p := backendTestPlan()
		p.Bridge.RemoteDir = "/etc/ultra-relay"
		p.SSH = installplan.SSHConfig{User: "root", Identity: filepath.Join(root, "identity")}
		remote := false
		p.ControllerLocal = &remote
		p.ControllerLocalTarget = p.Bridge.SSHHost + "|" + p.Bridge.Address
		return applyBackendDomain(p, config, "core.example.com", "example.com", action, "", pins, "ops@example.com")
	}
}

type backendOperationEvent struct {
	Action, ID, Job, Transaction string
}

func backendOperationEvents(t *testing.T, root string) []backendOperationEvent {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "operations"))
	if err != nil {
		t.Fatal(err)
	}
	var events []backendOperationEvent
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var event backendOperationEvent
		if err = json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	return events
}

func TestBackendDomainFailedActionCanRetryOrRollback(t *testing.T) {
	for _, action := range []string{"apply", "rollback"} {
		t.Run(action, func(t *testing.T) {
			root, run := backendOperationFixture(t)
			for _, fail := range []string{"apply", "rollback"} {
				if err := os.WriteFile(filepath.Join(root, "fail-"+fail), []byte("1"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := run("apply"); err == nil {
				t.Fatal("failed apply reported success")
			}
			events := backendOperationEvents(t, root)
			if len(events) != 3 || events[0].Action != "applying" || events[1].Action != "apply" || events[2].Action != "rollback" {
				t.Fatalf("unverified rollback released fleet: %+v", events)
			}
			failedJob := events[1].Job
			failed, err := os.ReadFile(filepath.Join(failedJob, "receipt.json"))
			if err != nil {
				t.Fatal(err)
			}
			for _, fail := range []string{"apply", "rollback"} {
				if err = os.Remove(filepath.Join(root, "fail-"+fail)); err != nil {
					t.Fatal(err)
				}
			}
			if err = run(action); err != nil {
				t.Fatalf("recovery could not resume existing reservation: %v", err)
			}
			events = backendOperationEvents(t, root)
			if len(events) != 6 || events[3].Action != "applying" || events[4].Action != action || events[5].Action != "released" || events[0].ID != events[3].ID || events[0].ID != events[5].ID {
				t.Fatalf("recovery lost lifecycle identity/order: %+v", events)
			}
			if events[4].Job == failedJob || events[4].Transaction != events[1].Transaction {
				t.Fatal("recovery reused immutable job or lost remote transaction")
			}
			after, err := os.ReadFile(filepath.Join(failedJob, "receipt.json"))
			if err != nil || string(after) != string(failed) {
				t.Fatal("recovery changed failed receipt", err)
			}
			canonical, err := os.ReadFile(filepath.Join(root, "install.config"))
			if err != nil || string(canonical) != "BOT_DOMAIN=old.example.com\n" {
				t.Fatal("non-accepting action changed canonical backend", err)
			}
		})
	}
}

func TestBackendDomainVerifiedAutomaticRollbackReleasesFleet(t *testing.T) {
	root, run := backendOperationFixture(t)
	if err := os.WriteFile(filepath.Join(root, "fail-apply"), []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run("apply"); err == nil {
		t.Fatal("failed apply hidden by successful rollback")
	}
	events := backendOperationEvents(t, root)
	if len(events) != 4 || events[2].Action != "rollback" || events[3].Action != "released" {
		t.Fatalf("verified rollback did not release fleet: %+v", events)
	}
	if err := os.Remove(filepath.Join(root, "fail-apply")); err != nil {
		t.Fatal(err)
	}
	if err := run("apply"); err != nil {
		t.Fatal(err)
	}
	events = backendOperationEvents(t, root)
	if len(events) != 7 || events[4].ID == events[0].ID || events[5].Action != "apply" || events[6].Action != "released" {
		t.Fatalf("new apply did not reverify in new reservation: %+v", events)
	}
}

func TestBackendDomainFailureBeforeStateCreationReleasesOnlyVerifiedOldBackend(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprint("partial=", partial), func(t *testing.T) {
			root, run := backendOperationFixture(t)
			source, err := filepath.Abs("../../deploy/ansible/library/ultra_backend_domain.py")
			if err != nil {
				t.Fatal(err)
			}
			// Exercise the real remote module against private local files. Apply
			// fails before prepare; recovery must prove the backend remains old.
			driver := fmt.Sprintf(`import importlib.util,json,pathlib,sys,types
root=pathlib.Path(__file__).parent/'remote'
fake=types.ModuleType('ansible.module_utils.basic');fake.AnsibleModule=object
sys.modules.update({'ansible':types.ModuleType('ansible'),'ansible.module_utils':types.ModuleType('ansible.module_utils'),'ansible.module_utils.basic':fake})
spec=importlib.util.spec_from_file_location('backend',%q)
backend=importlib.util.module_from_spec(spec);spec.loader.exec_module(backend)
backend.rollback(root/'transaction','old.example.com','core.example.com','sync.example.com',root)
`, source)
			for name, content := range map[string]string{
				"recover-pre-state.py":               driver,
				"fail-apply":                         "1",
				"remote/etc/ultra-relay/environment": "ULTRA_BOT_DOMAIN=old.example.com\n",
				"remote/etc/nginx/conf.d/site.conf":  "proxy_ssl_name old.example.com;\n",
			} {
				target := filepath.Join(root, name)
				if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(target, []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			manifestDirectory := filepath.Join(root, "remote/var/lib/ultra-ingress")
			if err = os.MkdirAll(manifestDirectory, 0700); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(manifestDirectory, "managed.json"), []byte(`{"/etc/nginx/conf.d/site.conf":"`+backendFixtureDigest([]byte("proxy_ssl_name old.example.com;\n"))+`"}`), 0600); err != nil {
				t.Fatal(err)
			}
			if partial {
				if err = os.WriteFile(filepath.Join(root, "remote/etc/ultra-relay/environment"), []byte("ULTRA_BOT_DOMAIN=core.example.com\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err = run("apply"); err == nil {
				t.Fatal("failed apply reported success")
			}
			events := backendOperationEvents(t, root)
			if partial {
				if len(events) != 3 || !strings.Contains(err.Error(), "rollback unconfirmed") {
					t.Fatalf("ambiguous state released lifecycle: %+v, %v", events, err)
				}
			} else if len(events) != 4 || events[3].Action != "released" {
				t.Fatalf("proven old backend left lifecycle held: %+v, %v", events, err)
			}
			if _, err = os.Stat(filepath.Join(root, "remote/transaction/state.json")); !os.IsNotExist(err) {
				t.Fatal("regression accidentally used a prepared transaction", err)
			}
		})
	}
}

func TestBackendDomainUnverifiedRollbackKeepsFleetReserved(t *testing.T) {
	root, run := backendOperationFixture(t)
	for _, marker := range []string{"fail-apply", "unverified-rollback"} {
		if err := os.WriteFile(filepath.Join(root, marker), []byte("1"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := run("apply"); err == nil || !strings.Contains(err.Error(), "rollback unconfirmed") {
		t.Fatal("unverified rollback accepted", err)
	}
	if events := backendOperationEvents(t, root); len(events) != 3 {
		t.Fatalf("unverified rollback released lifecycle: %+v", events)
	}
}

func TestBackendDomainFailedAcceptanceCanRetry(t *testing.T) {
	root, run := backendOperationFixture(t)
	if err := os.WriteFile(filepath.Join(root, "fail-accept"), []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run("accept"); err == nil {
		t.Fatal("failed acceptance reported success")
	}
	if err := os.Remove(filepath.Join(root, "fail-accept")); err != nil {
		t.Fatal(err)
	}
	if err := run("accept"); err != nil {
		t.Fatal("failed immutable receipt prevented acceptance retry", err)
	}
	events := backendOperationEvents(t, root)
	if len(events) != 5 || events[1].Action != "accept" || events[3].Action != "accept" || events[4].Action != "released" || events[0].ID != events[2].ID || events[1].Job == events[3].Job {
		t.Fatalf("acceptance retry lost reservation or reused job: %+v", events)
	}
	canonical, err := os.ReadFile(filepath.Join(root, "install.config"))
	if err != nil || string(canonical) != "BOT_DOMAIN=core.example.com\n" {
		t.Fatal("verified acceptance did not update canonical backend", err)
	}
}

func TestBackendDomainReleaseFailureCanRetry(t *testing.T) {
	root, run := backendOperationFixture(t)
	if err := os.WriteFile(filepath.Join(root, "fail-released"), []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run("apply"); err == nil {
		t.Fatal("release failure hidden")
	}
	if err := os.Remove(filepath.Join(root, "fail-released")); err != nil {
		t.Fatal(err)
	}
	if err := run("apply"); err != nil {
		t.Fatal("release recovery could not resume", err)
	}
	events := backendOperationEvents(t, root)
	if len(events) != 6 || events[0].ID != events[3].ID || events[1].Action != "apply" || events[4].Action != "apply" || events[1].Job == events[4].Job || events[5].Action != "released" {
		t.Fatalf("release retry did not reverify same reservation: %+v", events)
	}
}

func TestBackendDomainRequiresVerifiedOfflineRuntimeWithoutOverride(t *testing.T) {
	root, run := backendOperationFixture(t)
	t.Setenv("ULTRA_ANSIBLE_EXECUTABLE", "")
	if err := run("apply"); err == nil || !strings.Contains(err.Error(), "release") {
		t.Fatal("missing verified offline release was not rejected", err)
	}
	if _, err := os.Stat(filepath.Join(root, "operations")); !os.IsNotExist(err) {
		t.Fatal("reserved fleet or invoked bridge-only runtime before release verification", err)
	}
}

func backendFixtureDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
