package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	ansibleassets "github.com/NikitaDmitryuk/ultra/deploy/ansible"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

func retainedBridgeExitFixture() *retainedBridgeExit {
	return &retainedBridgeExit{
		FenceSHA256:       strings.Repeat("b", 64),
		SourceSHA256:      strings.Repeat("c", 64),
		SpecSHA256:        strings.Repeat("d", 64),
		CertificateSHA256: strings.Repeat("e", 64),
		TunnelUUID:        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
	}
}

func TestRetainedBridgeExplicitScopeAndPreservedExitRequired(t *testing.T) {
	for _, args := range [][]string{
		{"--bridge-only"},
		{"--bridge-only", "--retained-source-spec", "/private/source"},
		{"--bridge-only", "--accept-reimaged-fleet", "--retained-source-spec", "/private/source", "--authorize-new-fleet-key"},
		{"--accept-reimaged-fleet", "--authorize-new-fleet-key"},
	} {
		if err := runRetainedPrimaryCommand(args); err == nil || err.Error() != "retained_primary_explicit_operator_scope_required" {
			t.Fatalf("scope admitted: %v", err)
		}
	}
	for _, scenario := range []string{"missing", "wrong-mode", "invalid-fence", "invalid-spec", "invalid-certificate"} {
		t.Run(scenario, func(t *testing.T) {
			in := retainedRebuildFixture(t)
			in.BridgeOnly = true
			in.RetainedExit = retainedBridgeExitFixture()
			switch scenario {
			case "missing":
				in.RetainedExit = nil
			case "wrong-mode":
				in.BridgeOnly = false
			case "invalid-fence":
				in.RetainedExit.FenceSHA256 = ""
			case "invalid-spec":
				in.RetainedExit.SpecSHA256 = ""
			case "invalid-certificate":
				in.RetainedExit.CertificateSHA256 = ""
			}
			if validateRetainedPrimaryRebuild(in) == nil {
				t.Fatal("incomplete preserved identity admitted")
			}
		})
	}
}

func TestRetainedBridgeFixedOperationAndPostFenceFailure(t *testing.T) {
	for _, failAfter := range []bool{false, true} {
		in := retainedRebuildFixture(t)
		in.BridgeOnly = true
		in.RetainedExit = retainedBridgeExitFixture()
		calls := 0
		deps := retainedPrimaryRebuildDependencies{
			VerifyFence: func(context.Context, retainedPrimaryRebuildInput) error {
				calls++
				if failAfter && calls == 2 {
					return os.ErrPermission
				}
				return nil
			},
			ObservePrimary: func(context.Context, retainedPrimaryRebuildInput) (retainedPrimaryIdentity, error) {
				return in.Primary, nil
			},
			Run: func(_ context.Context, operation string, _ map[string]any, variables map[string]any, _, _, _ string) (deployansible.Receipt, error) {
				if operation != retainedBridgeRebuildOperation {
					t.Fatal("selected full fleet mutator")
				}
				return deployansible.Receipt{
					State:         "succeeded",
					RequestSHA256: strings.Repeat("a", 64),
					BinarySHA256:  strings.Repeat("a", 64),
					Result: deployansible.Result{
						Values: map[string]any{
							"verified":                  true,
							"retained_primary_verified": true,
							"relay_ready":               true,
							"bot_ready":                 true,
							"main_exit_ready":           true,
							"recovery_binding_sha256":   variables["ultra_retained_recovery_binding_sha256"],
						},
					},
				}, nil
			},
		}
		err := runRetainedPrimaryRebuild(context.Background(), in, deps)
		if (err != nil) != failAfter {
			t.Fatalf("result %v", err)
		}
		_, statErr := os.Stat(filepath.Join(in.Directory, "retained-primary-receipt.json"))
		if (statErr != nil) != failAfter {
			t.Fatal("published unverified preservation")
		}
	}
}

func TestRetainedBridgePlaybookPreservesApplicationAndPrimary(t *testing.T) {
	raw, err := ansibleassets.Bundle.ReadFile("playbooks/rebuild-retained-bridge.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, bad := range []string{"bootstrap-exit.yml", "bootstrap-postgres.yml", "bootstrap-automation.yml", "role: recovery_primary", "role: tunnel_certificate", "state: restarted", "tasks_from: authorize"} {
		if strings.Contains(text, bad) {
			t.Fatal("forbidden fleet mutation: " + bad)
		}
	}
	for _, needed := range []string{"BEGIN READ ONLY;", "retained_primary_after.stdout == retained_primary_before.stdout", "runtime-files.yml", "create: false", "backup: true", "ultra-bridge-recovery-", "force: false", "kind: bot"} {
		if !strings.Contains(text, needed) {
			t.Fatal("missing guard: " + needed)
		}
	}
}

func TestRetainedBridgeHistoricalSerializationUnchanged(t *testing.T) {
	in := retainedRebuildFixture(t)
	raw, _ := json.Marshal(in)
	if strings.Contains(string(raw), "BridgeOnly") || strings.Contains(string(raw), "RetainedExit") {
		t.Fatal("new empty fields changed historical binding")
	}
}

func TestRetainedBridgeFreshnessRecheckedBeforeMarkerClaim(t *testing.T) {
	for _, occupied := range []bool{false, true} {
		d := t.TempDir()
		state := filepath.Join(d, "state")
		system := filepath.Join(d, "systemd")
		relay := filepath.Join(d, "relay")
		if err := os.Mkdir(relay, 0700); err != nil {
			t.Fatal(err)
		}
		if occupied {
			if err := os.WriteFile(filepath.Join(relay, "spec.json"), []byte("existing"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		program := retainedFenceProgram(true)
		program = strings.ReplaceAll(program, "/var/lib/ultra-ansible", state)
		program = strings.ReplaceAll(program, "/etc/systemd/system", system)
		program = strings.ReplaceAll(program, "/etc/ultra-relay", relay)
		program = strings.ReplaceAll(program, ".st_uid==0", ".st_uid==os.geteuid()")
		program = "import subprocess,types\nsubprocess.run=lambda args,**kw:types.SimpleNamespace(returncode=0,stdout='not-found' if '--value' in args else 'LoadState=not-found\\nActiveState=inactive')\n" + program
		out, err := exec.Command("python3", "-u", "-c", program, strings.Repeat("a", 64)).CombinedOutput()
		if (err != nil) != occupied {
			t.Fatalf("%v %s", err, out)
		}
		_, statErr := os.Stat(filepath.Join(state, "retained-primary-admission.json"))
		if (statErr != nil) != occupied {
			t.Fatal("claimed admission on nonfresh bridge")
		}
	}
}

func TestRetainedBridgeReconciliationBindsSeparateFences(t *testing.T) {
	in, p := reconcileFixtureScoped(t, false, true)
	_, e, err := loadRetainedReconcile(p[0], p[1], p[2], p[3])
	if err != nil {
		t.Fatal(err)
	}
	if e.Fence != in.FenceEvidenceSHA256 || e.RetainedExit == nil || *e.RetainedExit != *in.RetainedExit ||
		e.RetainedExit.FenceSHA256 == e.Fence {
		t.Fatal("lost per-host identity")
	}
	path := filepath.Join(p[0], "execute/job.json")
	raw, _ := os.ReadFile(path)
	raw = bytes.ReplaceAll(raw, []byte(retainedBridgeRebuildOperation), []byte(retainedPrimaryRebuildOperation))
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = loadRetainedReconcile(p[0], p[1], p[2], p[3]); err == nil {
		t.Fatal("wrong mutator scope admitted")
	}
}

func TestRetainedBridgeExitLeaseChecksIdentityWithoutMutation(t *testing.T) {
	for _, scenario := range []string{"valid", "wrong-fence", "changed-spec", "changed-certificate", "activation"} {
		t.Run(scenario, func(t *testing.T) {
			program, state, _, _ := reconcileRemoteFixture(t)
			spec := []byte(`{"role":"exit","vless_port":443,"exit":{"tunnel_uuid":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}`)
			path := filepath.Join(filepath.Dir(state), "spec.json")
			if err := os.WriteFile(path, spec, 0600); err != nil {
				t.Fatal(err)
			}
			program = strings.ReplaceAll(program, "/etc/ultra-relay/spec.json", path)
			program = strings.ReplaceAll(
				program,
				" def recv(self,*args):",
				" def getpeercert(self,**kw):return b'fixture-certificate'\n def recv(self,*args):",
			)
			exit := retainedBridgeExitFixture()
			exit.FenceSHA256 = "fixture"
			exit.SpecSHA256 = digestSHA256(spec)
			exit.CertificateSHA256 = digestSHA256([]byte("fixture-certificate"))
			e := retainedReconcileEvidence{Protocol: "ultra-retained-primary-reconcile-v1", Fence: "new-bridge-fence", RetainedExit: exit}
			switch scenario {
			case "wrong-fence":
				exit.FenceSHA256 = "wrong"
			case "changed-spec":
				exit.SpecSHA256 = strings.Repeat("f", 64)
			case "changed-certificate":
				exit.CertificateSHA256 = strings.Repeat("f", 64)
			}
			raw, _ := json.Marshal(e)
			before, _ := os.ReadFile(filepath.Join(state, "retained-primary-admission.json"))
			c := exec.Command(
				"python3",
				"-u",
				"-c",
				program,
				"exit",
				"fixture",
				base64.StdEncoding.EncodeToString(raw),
				"443",
				"bot.example.com",
				"tunnel.example.com",
				"192.0.2.1",
			)
			input := "recheck\n"
			if scenario == "activation" {
				input = "activate-controller\n"
			}
			c.Stdin = strings.NewReader(input)
			out, err := c.CombinedOutput()
			if (err == nil) != (scenario == "valid") {
				t.Fatalf("%v %s", err, out)
			}
			after, _ := os.ReadFile(filepath.Join(state, "retained-primary-admission.json"))
			if !bytes.Equal(before, after) {
				t.Fatal("changed existing exit fence")
			}
			files, _ := filepath.Glob(filepath.Join(state, "retained-primary-controller-*"))
			if len(files) != 0 {
				t.Fatal("exit controller activated")
			}
		})
	}
}
