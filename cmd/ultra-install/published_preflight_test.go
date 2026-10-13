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
	p := installplan.LegacyValuesToPlan(map[string]string{"BRIDGE": "192.0.2.1", "EXIT": "192.0.2.2", "REALITY_DEST": "example.com:443"})
	p.Automation = &installplan.AutomationConfig{Version: "v1.2.3", ReleaseDir: dir, AgeRecipient: "age1fixture", BridgeProvider: "a", BridgeIPv4: "192.0.2.1", BridgeURL: "https://sync.example.com/healthz", KnownHostsFile: "/pins", StaticNodes: []installplan.AutomationNode{{Name: "NL", Address: "192.0.2.2", Provider: "a"}}, Ingress: &installplan.AutomationIngress{Domain: "edge.example.com", Email: "operator@example.com", Path: "/connect", PublicHost: "192.0.2.1", BackendPort: 18080}}
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
	fake := `import json,os,shlex,sys
script=shlex.split(sys.argv[-1])[-1]
with open(os.environ['ULTRA_PREFLIGHT_TEST_LOG'],'a') as f:f.write(json.dumps(script)+'\n')
if script.startswith('if test -f '):print('yes',end='')
elif script=='dpkg --print-architecture':print('amd64')
elif script.startswith('cat ') and 'spec.json' in script:print(json.dumps({'role':'bridge','primary_xhttp':{'server_name':'old.example.com','host':'192.0.2.1','port':443,'path':'/connect','backend_port':18080}}))
else:sys.exit(93)
`
	for _, name := range []string{"ssh", "scp"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!"+python+"\n"+fake), 0700); err != nil {
			t.Fatal(err)
		}
	}
	log := filepath.Join(dir, "calls.jsonl")
	cmd := exec.Command(os.Args[0], "-test.run=^TestPublishedApplyPreflightProcess$")
	cmd.Env = append(os.Environ(), "ULTRA_PREFLIGHT_TEST_PLAN="+plan, "ULTRA_PREFLIGHT_TEST_LOG="+log, "PATH="+dir+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "published_ingress_change_requires_explicit_cutover") {
		t.Fatalf("expected preflight rejection, got %v: %s", err, out)
	}
	calls, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(calls)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected only existence, architecture, spec reads before rejection; got %s", calls)
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
