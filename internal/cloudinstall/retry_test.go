package cloudinstall

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

// Persist through JSON just like CloudRepo, then reconstruct the service and
// worker so neither in-memory state nor a fake configurer can hide stale receipts.
type retryStore struct {
	cloud.Store
	body []byte
}

func (s *retryStore) Get(context.Context, string) (op cloud.Operation, err error) {
	err = json.Unmarshal(s.body, &op)
	return
}
func (s *retryStore) Save(_ context.Context, op cloud.Operation) (err error) {
	s.body, err = json.Marshal(op)
	return
}
func (s *retryStore) Lock(context.Context) (func(), error)               { return func() {}, nil }
func (s *retryStore) Audit(context.Context, int64, string, string) error { return nil }
func (s *retryStore) RecordEvent(context.Context, cloud.Event) error     { return nil }
func (s *retryStore) List(ctx context.Context) ([]cloud.Operation, error) {
	op, err := s.Get(ctx, "")
	return []cloud.Operation{op}, err
}

type retryProvider struct {
	cloud.Provider
	creates int
}

func (p *retryProvider) Get(context.Context, string) (cloud.Instance, error) {
	return cloud.Instance{ID: "purchased", Status: "active", IP: "192.0.2.2"}, nil
}
func (p *retryProvider) Create(context.Context, cloud.CreateRequest) (cloud.Instance, error) {
	p.creates++
	return cloud.Instance{}, cloud.ErrConflict
}

type retryInstaller struct {
	cloud.Provisioner
	p       *Provisioner
	binary  string
	request deployansible.ExitRequest
}

func (p retryInstaller) Install(ctx context.Context, op *cloud.Operation, _ cloud.Instance) error {
	_, err := p.p.configureExit(ctx, op, p.binary, p.request)
	return err
}

func TestAuthorizedCloudRetryEscapesFailedWorkerReceipt(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	root := t.TempDir()
	socket, state := filepath.Join(root, "worker.sock"), filepath.Join(root, "state")
	stub, calls := filepath.Join(root, "ansible-playbook"), filepath.Join(root, "calls")
	// This fixture runs the real controller without the host systemd manager.
	// Attest only its copied controller's normal completion, never production
	// code or the Status gate. Both failed and successful attempts retain their
	// exact real callback/completion bytes and ordinary broker restart behavior.
	originalNamespace := fixtureExecutionNamespace
	t.Cleanup(func() { fixtureExecutionNamespace = originalNamespace })
	fixtureExecutionNamespace = func(directory string) string {
		namespace := originalNamespace(directory)
		if !strings.HasPrefix(directory, state+string(os.PathSeparator)) {
			return namespace
		}
		controller := filepath.Join(directory, "bundle", "controller.py")
		source, e := os.ReadFile(controller)
		if e != nil || strings.Contains(string(source), "# rootless cloud cleanup fixture") {
			return namespace
		}
		insertion := `    # rootless cloud cleanup fixture: the test owns this copied controller.
    proof = {'schema': 1, 'fence': fence, 'mode': 'transient',
             'unit': 'ultra-execution-' + fence['generation'] + '.service',
             'invocation_id': 'a' * 32,
             'chain': [{'pid': 123, 'parent': 1, 'starttime': '99',
                        'group': '/system.slice/ultra-execution-' + fence['generation'] + '.service',
                        'executable_sha256': 'a' * 64, 'argv_sha256': 'b' * 64}]}
    atomic(directory / 'execution-containment.json', proof)
    atomic(directory / ('execution-drain-' + fence['generation'] + '.json'), {
        'proof': proof, 'completion_sha256': hashlib.sha256(
            load_private(directory / 'execution-completion.json', raw=True)).hexdigest()})
`
		marker := "    if os.environ.get('ULTRA_EXECUTION_GENERATION') or ("
		changed := strings.Replace(string(source), marker, insertion+marker, 1)
		if changed == string(source) {
			return namespace
		}
		// Reseal only this test-owned copy before the first fence/dispatch. The
		// production collector/status must see its exact original frozen inventory.
		if _, e = os.Lstat(filepath.Join(namespace, "execution-fence.json")); e == nil || !os.IsNotExist(e) {
			t.Error("fixture transform attempted after fence publication")
			return namespace
		}
		if e = os.WriteFile(controller, []byte(changed), 0600); e != nil {
			t.Error(e)
			return namespace
		}
		jobRaw, e := os.ReadFile(filepath.Join(directory, "job.json"))
		if e != nil {
			t.Error(e)
			return namespace
		}
		var job struct {
			Request string `json:"request_sha256"`
		}
		if e = json.Unmarshal(jobRaw, &job); e != nil {
			t.Error(e)
			return namespace
		}
		ownership := filepath.Join(directory, "bundle.retention.json")
		if e = os.Remove(ownership); e != nil && !os.IsNotExist(e) {
			t.Error(e)
			return namespace
		}
		if e = deployansible.WriteRetentionReceipt(filepath.Join(directory, "bundle"), filepath.Join(directory, "bundle"), ownership, map[string]string{"request_sha256": job.Request}); e != nil {
			t.Error(e)
		}
		return namespace
	}
	source := "#!" + python + "\n" + `import json,pathlib,sys
counter=pathlib.Path(` + "'" + calls + "'" + `)
count=int(counter.read_text())+1 if counter.exists() else 1
counter.write_text(str(count))
if count == 1:
 # A completed remote task failure has a terminal callback; bare process exit
 # would leave the global execution fence closed and must never permit retry.
 import os, types, importlib.util
 base=types.ModuleType('ansible.plugins.callback');base.CallbackBase=object
 sys.modules['ansible']=types.ModuleType('ansible')
 sys.modules['ansible.plugins']=types.ModuleType('ansible.plugins')
 sys.modules['ansible.plugins.callback']=base
 spec=importlib.util.spec_from_file_location('fixture_safe_result',pathlib.Path(os.environ['ULTRA_ANSIBLE_SOURCE_ROOT'])/'callback_plugins'/'safe_result.py')
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 callback=module.CallbackModule()
 host=types.SimpleNamespace(name='fixture_target')
 task=types.SimpleNamespace(_uuid='completed_fixture_task',async_val=0)
 callback.execution_task(host,task);callback.execution_task(host,task,True)
 callback.v2_playbook_on_stats(types.SimpleNamespace(processed={'fixture_target':1},summarize=lambda host:{'failures':1,'unreachable':0}))
 sys.exit(2)
value=json.loads((pathlib.Path(sys.argv[-1][1:]).parent/'variables.json').read_text())
path=pathlib.Path(value['ultra_result_file'])
path.write_text(json.dumps({'cert_pin':'b'*64}))
path.chmod(0o600)
`
	if err := os.WriteFile(stub, []byte(source), 0700); err != nil {
		t.Fatal(err)
	}
	start := func() func() {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- deployansible.Serve(ctx, socket, state, python, stub, uint32(os.Getuid())) }()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if (deployansible.Client{Socket: socket}).Ready(context.Background()) == nil {
				return func() {
					cancel()
					if err := <-done; err != nil {
						t.Error(err)
					}
				}
			}
			select {
			case err := <-done:
				cancel()
				t.Fatalf("worker exited: %v", err)
			default:
			}
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
		t.Fatal("worker did not start")
		return nil
	}
	stop := start()
	defer func() { stop() }()
	binary, identity, pins := filepath.Join(root, "relay"), filepath.Join(root, "identity"), filepath.Join(root, "pins")
	for _, path := range []string{binary, identity, pins} {
		if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	request := deployansible.ExitRequest{
		Host:       "192.0.2.2",
		User:       "root",
		Identity:   identity,
		KnownHosts: pins,
		BridgeIPv4: "192.0.2.1",
		Spec: config.Spec{
			Role:          config.RoleExit,
			MimicPreset:   "steamlike",
			ListenAddress: "0.0.0.0",
			VLESSPort:     8443,
			Exit:          config.ExitTunnelSpec{TunnelUUID: "11111111-2222-3333-4444-555555555555"},
			ExitCertPaths: config.CertPaths{CertFile: "/etc/ultra-relay/fullchain.pem", KeyFile: "/etc/ultra-relay/privkey.pem"},
			SplithttpHost: "example.com",
			SplithttpPath: "/fixture",
		},
	}
	op := cloud.Operation{
		ID:         "11111111-2222-3333-4444-555555555555",
		State:      "pending",
		Phase:      "install",
		InstanceID: "purchased",
		ExitID:     "staged",
		FirewallID: "firewall",
		Charged:    true,
	}
	p := &Provisioner{Configurer: deployansible.Client{Socket: socket}}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	store := &retryStore{}
	if err := store.Save(ctx, op); err != nil {
		t.Fatal(err)
	}
	provider := &retryProvider{}
	service := &cloud.Service{Store: store, API: provider, Provisioner: retryInstaller{p: p, binary: binary, request: request}}
	if err := service.Step(ctx); err == nil {
		t.Fatal("first transient failure accepted")
	}
	op, err = store.Get(ctx, op.ID)
	if err != nil || op.State != "failed" {
		t.Fatalf("failure not saved: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := service.Step(ctx); err != nil {
			t.Fatal(err)
		}
	}
	first, err := configurationJobID(op.ID, binary, request)
	if err != nil {
		t.Fatal(err)
	}
	failedReceipt, err := os.ReadFile(filepath.Join(state, first, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.configureExit(ctx, &op, binary, request); err == nil {
		t.Fatal("terminal failure automatically reset")
	}
	if err := service.Action(ctx, 1, op.ID, "retry"); err != nil {
		t.Fatal(err)
	}
	op, err = store.Get(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if op.State != "pending" || op.Phase != "install" || op.InstanceID != "purchased" || op.ExitID != "staged" ||
		op.FirewallID != "firewall" ||
		!op.Charged {
		t.Fatal("retry changed purchase identity")
	}
	stop()
	stop = start()
	p = &Provisioner{Configurer: deployansible.Client{Socket: socket}}
	service = &cloud.Service{Store: store, API: provider, Provisioner: retryInstaller{p: p, binary: binary, request: request}}
	if err := service.Step(ctx); err != nil {
		t.Fatalf("explicit retry stayed stuck on failed receipt: %v", err)
	}
	op, err = store.Get(ctx, op.ID)
	if err != nil || op.Phase != "verify" || provider.creates != 0 {
		t.Fatal("retry did not resume existing VM", err)
	}
	if _, err := p.configureExit(ctx, &op, binary, request); err != nil {
		t.Fatalf("completed retry lost identity: %v", err)
	}
	count, err := os.ReadFile(calls)
	if err != nil || string(count) != "2" {
		t.Fatalf("execution count %s: %v", count, err)
	}
	retained, err := os.ReadFile(filepath.Join(state, first, "receipt.json"))
	if err != nil || string(retained) != string(failedReceipt) {
		t.Fatal("failed attempt history overwritten")
	}
	entries, err := os.ReadDir(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(state, entry.Name(), "request.json"))
		if err != nil {
			t.Fatal(err)
		}
		var saved deployansible.ExitRequest
		if json.Unmarshal(raw, &saved) != nil || saved.Spec.Exit.TunnelUUID != request.Spec.Exit.TunnelUUID {
			t.Fatal("retry rotated tunnel UUID")
		}
	}
}
