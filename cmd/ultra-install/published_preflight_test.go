package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPublishedApplyPreflightProcess(t *testing.T) {
	if file := os.Getenv("ULTRA_PREFLIGHT_TEST_PLAN"); file != "" {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var p installplan.InstallPlan
		if err = json.Unmarshal(raw, &p); err != nil {
			t.Fatal(err)
		}
		applyPlanN(&p, "jsonl")
		return
	}
	dir := t.TempDir()
	p := installplan.LegacyValuesToPlan(map[string]string{"BRIDGE": "192.0.2.1", "EXIT": "192.0.2.2", "REALITY_DEST": "example.com:443", "IDENTITY": filepath.Join(dir, "identity")})
	p.Automation = &installplan.AutomationConfig{Version: "v1.2.3", ReleaseDir: dir, AgeRecipient: "age1fixture", BridgeProvider: "a", BridgeIPv4: "192.0.2.1", BridgeURL: "https://sync.example.com/healthz", KnownHostsFile: filepath.Join(dir, "pins"), StaticNodes: []installplan.AutomationNode{{Name: "NL", Address: "192.0.2.2", Provider: "a"}}, Ingress: &installplan.AutomationIngress{Domain: "edge.example.com", Email: "operator@example.com", Path: "/connect", PublicHost: "192.0.2.1", BackendPort: 18080}}
	var assets []map[string]any
	for _, name := range []string{"ultra-relay-linux-amd64", "ultra-relay-linux-arm64", "ultra-bot-linux-amd64", "ultra-bot-linux-arm64", "ultra-client-linux-amd64", "ultra-client-linux-arm64", "ultra-recovery.tar.gz"} {
		data := []byte(name)
		sum := sha256.Sum256(data)
		assets = append(assets, map[string]any{"name": name, "size": len(data), "sha256": hex.EncodeToString(sum[:])})
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := json.Marshal(map[string]any{"version": "v1.2.3", "capabilities": []string{"service-access-v1"}, "assets": assets})
	if err := os.WriteFile(filepath.Join(dir, "release-manifest.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(p)
	plan := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(plan, raw, 0600); err != nil {
		t.Fatal(err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pins"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "calls.jsonl")
	fake := `import base64,json,pathlib,sys
inv=pathlib.Path(sys.argv[sys.argv.index('-i')+1]);req=json.loads((inv.parent/'request.json').read_text())
if pathlib.Path(sys.argv[sys.argv.index('-i')+2]).stem != 'inspect-bootstrap':sys.exit(93)
common=req['inventory']['all']['vars'];directory=pathlib.Path(common['ultra_inspect_dir'])
for group in ('bridge','exits'):
 for alias in req['inventory']['all']['children'][group]['hosts']:
  files=[]
  if alias=='bridge':
   spec={'role':'bridge','primary_xhttp':{'server_name':'old.example.com','host':'192.0.2.1','port':443,'path':'/connect','backend_port':18080}}
   files=[{'source':'/etc/ultra-relay/spec.json','content':base64.b64encode(json.dumps(spec).encode()).decode()}]
  (directory/(alias+'.json')).write_text(json.dumps({'architecture':'amd64','files':files}))
(inv.parent/'result.json').write_text('{"verified":true}');(inv.parent/'result.json').chmod(0o600)
pathlib.Path(LOG).write_text('inspect-bootstrap\n')
`
	fake = strings.Replace(fake, "LOG", strconv.Quote(log), 1)
	executable := filepath.Join(dir, "ansible-playbook")
	if err := os.WriteFile(executable, []byte("#!"+python+"\n"+fake), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestPublishedApplyPreflightProcess$")
	cmd.Env = append(os.Environ(), "ULTRA_PREFLIGHT_TEST_PLAN="+plan, "ULTRA_PREFLIGHT_TEST_LOG="+log, "ULTRA_ANSIBLE_EXECUTABLE="+executable, "ULTRA_INSTALL_STATE_DIR="+filepath.Join(dir, "state"))
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "published_ingress_change_requires_explicit_cutover") {
		t.Fatalf("expected preflight rejection, got %v: %s", err, out)
	}
	calls, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(calls)), "\n")
	if len(lines) != 1 || lines[0] != "inspect-bootstrap" {
		t.Fatalf("expected only read-only Ansible inspection before rejection; got %s", calls)
	}
}

func TestPublishedIngressPlanAllowsExactReuseAndUnpublishedStage(t *testing.T) {
	p := &installplan.InstallPlan{SchemaVersion: 2, Automation: &installplan.AutomationConfig{Ingress: &installplan.AutomationIngress{Domain: "edge.example.com", PublicHost: "192.0.2.1", Path: "/connect", BackendPort: 18080}}}
	spec := &config.Spec{PrimaryXHTTP: &config.PrimaryXHTTPIngress{Host: "192.0.2.1", BackendPort: 18080, PublicXHTTPTLSSpec: config.PublicXHTTPTLSSpec{ServerName: "edge.example.com", Port: 443, Path: "/connect"}}}
	if err := checkPublishedIngressPlan(p, spec); err != nil {
		t.Fatal(err)
	}
	spec.PrimaryXHTTP.ServerName = "old.example.com"
	if checkPublishedIngressPlan(p, spec) == nil {
		t.Fatal("implicit published=true must be guarded")
	}
	unpublished := false
	spec.PrimaryXHTTP.Published = &unpublished
	if err := checkPublishedIngressPlan(p, spec); err != nil {
		t.Fatal(err)
	}
}

func TestPublishedIngressAdoptionRejectsUnpublishedAndGatewayChange(t *testing.T) {
	p := &installplan.InstallPlan{SchemaVersion: 2, AdoptRuntime: true, Automation: &installplan.AutomationConfig{Ingress: &installplan.AutomationIngress{Domain: "edge.example.com", PublicHost: "192.0.2.1", Path: "/connect", BackendPort: 18080, GatewayPort: 18081}}}
	spec := &config.Spec{GatewayVLESSPort: 18081, PrimaryXHTTP: &config.PrimaryXHTTPIngress{Host: "192.0.2.1", BackendPort: 18080, PublicXHTTPTLSSpec: config.PublicXHTTPTLSSpec{ServerName: "edge.example.com", Port: 443, Path: "/connect"}}}
	if err := checkPublishedIngressPlan(p, spec); err != nil {
		t.Fatal(err)
	}
	spec.GatewayVLESSPort = 18082
	if checkPublishedIngressPlan(p, spec) == nil {
		t.Fatal("adoption changed installed gateway")
	}
	spec.GatewayVLESSPort = 18081
	unpublished := false
	spec.PrimaryXHTTP.Published = &unpublished
	if checkPublishedIngressPlan(p, spec) == nil {
		t.Fatal("adoption accepted unproved publication")
	}
}
