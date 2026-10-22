package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

func reconcileFixture(t *testing.T) (retainedPrimaryRebuildInput, []string) {
	return reconcileFixtureDNS(t, false)
}

func reconcileFixtureDNS(t *testing.T, historical bool) (retainedPrimaryRebuildInput, []string) {
	return reconcileFixtureScoped(t, historical, false)
}

func reconcileFixtureScoped(t *testing.T, historical, bridge bool) (retainedPrimaryRebuildInput, []string) {
	t.Helper()
	in := retainedRebuildFixture(t)
	if bridge {
		in.BridgeOnly = true
		in.RetainedExit = retainedBridgeExitFixture()
	}
	paths := []string{
		in.Directory,
		filepath.Join(in.Directory, "config"),
		filepath.Join(in.Directory, "manifest"),
		filepath.Join(in.Directory, "journal"),
	}
	for i, p := range paths[1:] {
		if err := os.WriteFile(p, []byte(strings.Repeat("fixture", i+1)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(paths[1])
	in.ConfigSHA256 = digestSHA256(b)
	b, _ = os.ReadFile(paths[2])
	in.ManifestSHA256 = digestSHA256(b)
	b, _ = os.ReadFile(paths[3])
	in.JournalSHA256 = digestSHA256(b)
	in.Variables["large_integer"] = json.Number("9007199254740993")
	if historical {
		in.Variables["ultra_dns_config"] = struct {
			Zone  string      `json:"zone"`
			API   string      `json:"api"`
			Large json.Number `json:"large"`
		}{"example.net", "fixture", json.Number("9007199254740993")}
	}
	write := func(p string, v any) {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(p, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(in.Directory, "prepared-input.json"), in)
	normalized, _ := json.Marshal(in)
	binding := digestSHA256(normalized)
	vars := map[string]any{}
	for k, v := range in.Variables {
		vars[k] = v
	}
	vars["ultra_retained_primary"] = map[string]any{
		"system_identifier": in.Primary.SystemIdentifier,
		"database":          in.Primary.Database,
		"database_oid":      in.Primary.DatabaseOID,
		"migrations_sha256": in.Primary.MigrationsSHA256,
	}
	vars["ultra_retained_candidate_migration_versions"] = in.CandidateMigrationVersions
	vars["ultra_retained_recovery_binding_sha256"] = binding
	vars["ultra_bootstrap_exit_host"] = "exit_0"
	vars["ultra_preserve_runtime"] = false
	execute := filepath.Join(in.Directory, "execute")
	bundle := filepath.Join(execute, "bundle")
	if err := os.MkdirAll(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(execute, "request.json"), map[string]any{"inventory": in.Inventory, "variables": vars})
	request, _ := os.ReadFile(filepath.Join(execute, "request.json"))
	hash := digestSHA256(request)
	result := map[string]any{
		"verified":                  true,
		"retained_primary_verified": true,
		"relay_ready":               true,
		"bot_ready":                 true,
		"main_exit_ready":           true,
		"recovery_binding_sha256":   binding,
	}
	write(
		filepath.Join(execute, "job.json"),
		map[string]any{"schema_version": 1, "operation": retainedRebuildOperation(in), "request_sha256": hash, "binary_sha256": hash},
	)
	write(
		filepath.Join(execute, "receipt.json"),
		map[string]any{
			"schema_version": 1,
			"operation":      retainedRebuildOperation(in),
			"request_sha256": hash,
			"binary_sha256":  hash,
			"state":          "succeeded",
			"result":         result,
		},
	)
	write(filepath.Join(execute, "result.json"), result)
	if err := os.WriteFile(filepath.Join(bundle, "controller.py"), []byte("raise Exception('must never execute')"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := deployansible.WriteRetentionReceipt(bundle, bundle, filepath.Join(execute, "bundle.retention.json"), map[string]string{"request_sha256": hash}); err != nil {
		t.Fatal(err)
	}
	return in, paths
}

func TestRetainedReconcileHistoricalTypedDNSOrder(t *testing.T) {
	_, p := reconcileFixtureDNS(t, true)
	in, e, err := loadRetainedReconcile(p[0], p[1], p[2], p[3])
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(p[0], "prepared-input.json"))
	var compact bytes.Buffer
	_ = json.Compact(&compact, raw)
	normalized, _ := json.Marshal(in)
	if e.Binding != digestSHA256(compact.Bytes()) || e.Binding == digestSHA256(normalized) {
		t.Fatal("historical typed DNS serializer was not retained")
	}
	if in.Variables["ultra_dns_config"].(map[string]any)["large"] != json.Number("9007199254740993") {
		t.Fatal("DNS integer precision lost")
	}
}

func TestRetainedReconcileRejectsDuplicateUnknownAndUncalculatedBinding(t *testing.T) {
	for _, kind := range []string{"duplicate-prepared", "duplicate-request", "unknown-prepared", "unknown-request", "uncalculated-binding"} {
		t.Run(kind, func(t *testing.T) {
			_, p := reconcileFixtureDNS(t, true)
			path := filepath.Join(p[0], "execute/request.json")
			if strings.HasSuffix(kind, "prepared") {
				path = filepath.Join(p[0], "prepared-input.json")
			}
			raw, _ := os.ReadFile(path)
			switch kind {
			case "duplicate-prepared", "duplicate-request":
				raw = bytes.Replace(raw, []byte(`"large_integer":`), []byte(`"large_integer":0,"large_integer":`), 1)
			case "unknown-prepared", "unknown-request":
				raw = append([]byte(`{"unexpected":true,`), raw[1:]...)
			case "uncalculated-binding":
				var request map[string]any
				_ = decodeRetainedReconcile(raw, &request)
				request["variables"].(map[string]any)["ultra_retained_recovery_binding_sha256"] = strings.Repeat("d", 64)
				raw, _ = json.Marshal(request)
			}
			_ = os.WriteFile(path, raw, 0600)
			if _, _, err := loadRetainedReconcile(p[0], p[1], p[2], p[3]); err == nil {
				t.Fatal("unbound/ambiguous proof accepted")
			}
		})
	}
}

func TestRetainedReconcileHistoricalSuccessWithoutRuntimeOrWrapper(t *testing.T) {
	in, p := reconcileFixture(t)
	// Neither historical executable nor wrapper receipt is required or created.
	got, e, err := loadRetainedReconcile(p[0], p[1], p[2], p[3])
	if err != nil {
		t.Fatal(err)
	}
	if got.FenceEvidenceSHA256 != in.FenceEvidenceSHA256 || e.Fence == e.Binding {
		t.Fatal("lost distinct fence/input bindings")
	}
	if _, err = os.Stat(filepath.Join(in.Directory, "retained-primary-receipt.json")); !os.IsNotExist(err) {
		t.Fatal("rewrote wrapper history")
	}
	if got.Variables["large_integer"] != json.Number("9007199254740993") {
		t.Fatal("integer precision lost")
	}
}

func TestRetainedReconcileRejectsChangedProofs(t *testing.T) {
	for _, kind := range []string{"config", "request", "failed", "missing-operation", "result-binding", "bundle", "extra-bundle", "missing-bundle", "symlink", "public"} {
		t.Run(kind, func(t *testing.T) {
			in, p := reconcileFixture(t)
			ex := filepath.Join(in.Directory, "execute")
			mutate := func(name string, f func(map[string]any)) {
				path := filepath.Join(ex, name)
				raw, _ := os.ReadFile(path)
				v := map[string]any{}
				_ = json.Unmarshal(raw, &v)
				f(v)
				raw, _ = json.Marshal(v)
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "config":
				_ = os.WriteFile(p[1], []byte("changed"), 0600)
			case "request":
				_ = os.WriteFile(filepath.Join(ex, "request.json"), []byte(`{}`), 0600)
			case "failed":
				mutate("receipt.json", func(v map[string]any) { v["state"] = "failed" })
			case "missing-operation":
				mutate("receipt.json", func(v map[string]any) { delete(v, "operation") })
			case "result-binding":
				mutate("result.json", func(v map[string]any) { v["recovery_binding_sha256"] = strings.Repeat("0", 64) })
				mutate("receipt.json", func(v map[string]any) {
					v["result"].(map[string]any)["recovery_binding_sha256"] = strings.Repeat("0", 64)
				})
			case "bundle":
				_ = os.WriteFile(filepath.Join(ex, "bundle/controller.py"), []byte("changed"), 0600)
			case "extra-bundle":
				_ = os.WriteFile(filepath.Join(ex, "bundle/extra.py"), []byte("extra"), 0600)
			case "missing-bundle":
				_ = os.Remove(filepath.Join(ex, "bundle/controller.py"))
			case "symlink":
				path := filepath.Join(ex, "result.json")
				_ = os.Rename(path, path+".real")
				_ = os.Symlink(path+".real", path)
			case "public":
				_ = os.Chmod(filepath.Join(ex, "receipt.json"), 0644)
			}
			if _, _, err := loadRetainedReconcile(p[0], p[1], p[2], p[3]); err == nil {
				t.Fatal("changed proof accepted")
			}
		})
	}
}

func TestRetainedReconcileReceiptCreateOnlyReplay(t *testing.T) {
	d := t.TempDir()
	_ = os.Chmod(d, 0700)
	p := filepath.Join(d, "evidence.json")
	for i := 0; i < 2; i++ {
		if err := publishRetainedReconcile(p, []byte(`{"verified":true}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := publishRetainedReconcile(p, []byte(`{"different":true}`)); err == nil {
		t.Fatal("receipt overwritten")
	}
}

func reconcileRemoteFixture(t *testing.T) (string, string, string, string) {
	t.Helper()
	d := t.TempDir()
	state := filepath.Join(d, "state")
	system := filepath.Join(d, "systemd")
	proc := filepath.Join(d, "proc")
	for _, p := range []string{state, filepath.Join(state, "operator-inputs"), system, proc} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"infrastructure.lock", "operator-inputs/manual-deploy.lock"} {
		if err := os.WriteFile(filepath.Join(state, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name, raw string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(state, name), []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("retained-primary-admission.json", `{"protocol":"retained-primary-admission-v1","binding_sha256":"fixture"}`)
	write("lifecycle.json", `{"phase":"released"}`)
	for _, unit := range []string{"ultra-ansible-controller.service", "ultra-recovery-reconcile.service", "ultra-recovery-reconcile.timer"} {
		dir := filepath.Join(system, unit+".d")
		_ = os.MkdirAll(dir, 0755)
		_ = os.WriteFile(
			filepath.Join(dir, "90-retained-primary.conf"),
			[]byte(strings.ReplaceAll(retainedFenceDropin, "/var/lib/ultra-ansible", state)),
			0644,
		)
	}
	_ = os.WriteFile(filepath.Join(system, "controller.service"), []byte("fixture"), 0644)
	program := strings.ReplaceAll(retainedReconcileRemote, "/var/lib/ultra-ansible", state)
	program = strings.ReplaceAll(program, "/etc/systemd/system", system)
	program = strings.ReplaceAll(program, "Path('/proc')", "Path("+fmtPython(proc)+")")
	program = strings.ReplaceAll(program, "for ancestor in [p]+list(p.parents):", "for ancestor in [p]:")
	program = strings.ReplaceAll(program, "s.st_uid==0", "s.st_uid==os.geteuid()")
	// Only host interfaces are mocked; filesystem locks, durable publication,
	// census, queue parsing, EOF and authorization checks use the real program.
	mock := `import subprocess,types,socket,ssl,http.client,json
def run(args,**kw):
 if args[1]=='show':
  unit=args[2]
  from pathlib import Path
  text=Path(` + fmtPython(system) + `+'/'+unit+'.d/90-retained-primary.conf').read_text()
  refused='no' if 'RefuseManualStart=no' in text else 'yes'
  return types.SimpleNamespace(returncode=0,stdout='LoadState=loaded\nActiveState=inactive\nRefuseManualStart='+refused+'\nUnitFileState=disabled\nFragmentPath='+` + fmtPython(filepath.Join(system, "controller.service")) + `+'\n')
 return types.SimpleNamespace(returncode=0,stdout='')
subprocess.run=run
class Connection:
 def __enter__(self):return self
 def __exit__(self,*args):pass
 def sendall(self,*args):pass
 def recv(self,*args):return b'{"state":"ready"}'
 def settimeout(self,*args):pass
 def connect(self,*args):pass
socket.create_connection=lambda *a,**kw:Connection()
socket.socket=lambda *a,**kw:Connection()
ssl.create_default_context=lambda:types.SimpleNamespace(wrap_socket=lambda *a,**kw:Connection())
http.client.HTTPResponse=lambda *a:types.SimpleNamespace(begin=lambda:None,read=lambda *a:b'',status=200)
`
	return mock + program, state, system, proc
}
func fmtPython(s string) string { raw, _ := json.Marshal(s); return string(raw) }

func runReconcileRemoteTest(t *testing.T, program, input string) ([]byte, error) {
	t.Helper()
	e := retainedReconcileEvidence{Protocol: "ultra-retained-primary-reconcile-v1", Fence: "fixture"}
	raw, _ := json.Marshal(e)
	c := exec.Command(
		"python3",
		"-u",
		"-c",
		program,
		"bridge",
		"fixture",
		base64.StdEncoding.EncodeToString(raw),
		"443",
		"bot.example.com",
		"tunnel.example.com",
		"192.0.2.1",
	)
	c.Stdin = strings.NewReader(input)
	return c.CombinedOutput()
}
func TestRetainedReconcileRemoteEOFAndActivation(t *testing.T) {
	for _, activate := range []bool{false, true} {
		t.Run(map[bool]string{false: "EOF", true: "activate"}[activate], func(t *testing.T) {
			program, state, system, _ := reconcileRemoteFixture(t)
			marker, _ := os.ReadFile(filepath.Join(state, "retained-primary-admission.json"))
			input := ""
			if activate {
				input = "activate-controller\n"
			}
			out, err := runReconcileRemoteTest(t, program, input)
			if err != nil {
				t.Fatalf("%v %s", err, out)
			}
			if bytes.Contains(out, []byte("activated")) != activate {
				t.Fatal(string(out))
			}
			after, _ := os.ReadFile(filepath.Join(state, "retained-primary-admission.json"))
			if !bytes.Equal(after, marker) {
				t.Fatal("admission marker changed")
			}
			for _, unit := range []string{"ultra-recovery-reconcile.service", "ultra-recovery-reconcile.timer"} {
				b, _ := os.ReadFile(filepath.Join(system, unit+".d/90-retained-primary.conf"))
				if string(b) != strings.ReplaceAll(retainedFenceDropin, "/var/lib/ultra-ansible", state) {
					t.Fatal("reconcile fence changed")
				}
			}
			if _, err := os.Lstat(filepath.Join(state, "retained-primary-admission-open")); !os.IsNotExist(err) {
				t.Fatal("shared admission opened")
			}
		})
	}
}
func TestRetainedReconcileRemoteRejectsUnsafeState(t *testing.T) {
	for _, kind := range []string{"wrong-marker", "opened", "applying", "orphan", "queued", "corrupt-terminal", "other-fence", "lock-busy"} {
		t.Run(kind, func(t *testing.T) {
			program, state, _, proc := reconcileRemoteFixture(t)
			switch kind {
			case "wrong-marker":
				_ = os.WriteFile(filepath.Join(state, "retained-primary-admission.json"), []byte(`{}`), 0600)
			case "opened":
				_ = os.WriteFile(filepath.Join(state, "retained-primary-admission-open"), nil, 0600)
			case "applying":
				_ = os.WriteFile(filepath.Join(state, "lifecycle.json"), []byte(`{"phase":"applying"}`), 0600)
			case "orphan":
				_ = os.Mkdir(filepath.Join(proc, "123"), 0700)
				_ = os.WriteFile(filepath.Join(proc, "123/cmdline"), []byte("python3\x00controller.py\x00"), 0600)
			case "queued", "corrupt-terminal":
				p := filepath.Join(state, "11111111-2222-3333-4444-555555555555")
				_ = os.Mkdir(p, 0700)
				_ = os.WriteFile(filepath.Join(p, "prepared"), nil, 0600)
				if kind == "corrupt-terminal" {
					_ = os.WriteFile(filepath.Join(p, "receipt.json"), []byte(`{"state":"succeeded"}`), 0600)
				}
			case "other-fence":
				_ = os.WriteFile(filepath.Join(state, "recovery-anchor.json"), []byte(`{}`), 0600)
			case "lock-busy":
				program = strings.Replace(
					program,
					"fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)",
					"(_ for _ in []).throw(BlockingIOError())",
					1,
				)
			}
			out, err := runReconcileRemoteTest(t, program, "activate-controller\n")
			if err == nil || bytes.Contains(out, []byte("activated\n")) {
				t.Fatalf("unsafe state accepted: %s", out)
			}
		})
	}
}

func TestRetainedReconcileRemoteCrashAuthorizationReplay(t *testing.T) {
	for _, point := range []string{"auth", "dropin", "start"} {
		t.Run(point, func(t *testing.T) {
			program, state, system, _ := reconcileRemoteFixture(t)
			needle := map[string]string{"auth": "publish(auth,receipt,0o600)", "dropin": "publish(dropin,opened.encode(),0o644,True)", "start": " subprocess.run(['systemctl','start',units[0]],check=True,timeout=30)"}[point]
			broken := strings.Replace(
				program,
				needle,
				needle+"\n"+map[string]string{"auth": "raise RuntimeError('crash')", "dropin": "raise RuntimeError('crash')", "start": " raise RuntimeError('crash')"}[point],
				1,
			)
			if out, err := runReconcileRemoteTest(t, broken, "activate-controller\n"); err == nil ||
				bytes.Contains(out, []byte("activated\n")) {
				t.Fatal("crash accepted")
			}
			if point == "start" {
				raw, _ := os.ReadFile(filepath.Join(system, "ultra-ansible-controller.service.d/90-retained-primary.conf"))
				if string(raw) != strings.ReplaceAll(retainedFenceDropin, "/var/lib/ultra-ansible", state) {
					t.Fatal("failed activation did not restore admission")
				}
			}
			// A retry uses exactly the same evidence and freshly executes all checks.
			if out, err := runReconcileRemoteTest(t, program, "activate-controller\n"); err != nil {
				t.Fatalf("same authorization could not recover stopped controller: %v %s", err, out)
			}
		})
	}
}
