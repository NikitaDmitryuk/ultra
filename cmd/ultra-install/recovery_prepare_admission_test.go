package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type recoveryAdmissionFixture struct {
	root, state, system, proc string
	proof                     recoveryPreparationAdmission
	program                   string
}

func preparationAdmissionFixture(t *testing.T) recoveryAdmissionFixture {
	t.Helper()
	root := t.TempDir()
	f := recoveryAdmissionFixture{
		root:   root,
		state:  filepath.Join(root, "state"),
		system: filepath.Join(root, "system"),
		proc:   filepath.Join(root, "proc"),
		proof: recoveryPreparationAdmission{
			"ultra-recovery-preparation-admission-v1",
			strings.Repeat("a", 64),
			strings.Repeat("b", 64),
			strings.Repeat("c", 64),
			"sealed",
		},
	}
	for _, path := range []string{f.state, filepath.Join(f.state, "operator-inputs"), filepath.Join(f.state, "operator"), f.system, f.proc} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path string, value any) {
		raw, _ := json.Marshal(value)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(
		filepath.Join(f.state, "retained-primary-admission.json"),
		map[string]any{"protocol": "retained-primary-admission-v1", "binding_sha256": f.proof.FenceSHA256},
	)
	write(filepath.Join(f.state, "lifecycle.json"), map[string]string{"phase": "released"})
	for _, path := range []string{"infrastructure.lock", "operator-inputs/manual-deploy.lock", "operator/infrastructure.lock"} {
		if err := os.WriteFile(filepath.Join(f.state, path), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, unit := range []string{"ultra-ansible-controller.service", "ultra-recovery-reconcile.service", "ultra-recovery-reconcile.timer"} {
		directory := filepath.Join(f.system, unit+".d")
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "90-retained-primary.conf"), []byte("[Unit]\nRefuseManualStart=yes\nConditionPathExists=/var/lib/ultra-ansible/retained-primary-admission-open\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	prefix := `import subprocess,json,pathlib,os
_fixture_root=pathlib.Path(` + fmtPython(root) + `)
def _fixture_run(args,**kwargs):
    unit=args[-1] if args[1]!='show' else args[2]
    if args[1]=='show':
        active=(_fixture_root/'active').exists() and unit=='ultra-ansible-controller.service'
        content=(_fixture_root/'system'/(unit+'.d')/'90-retained-primary.conf').read_text()
        return type('Result',(),{'returncode':0,'stdout':'LoadState=loaded\nActiveState='+('active' if active else 'inactive')+'\nRefuseManualStart='+('yes' if 'RefuseManualStart=yes' in content else 'no')+'\nUnitFileState=disabled\nMainPID='+('4242' if active else '0')+'\n'})()
    with (_fixture_root/'mutations').open('a') as stream:stream.write(json.dumps(args)+'\n')
    if args[1]=='stop' and unit=='ultra-ansible-controller.service':
        (_fixture_root/'active').unlink(missing_ok=True)
        proc=_fixture_root/'proc'/'4242'
        if proc.exists():
            for child in proc.iterdir():child.unlink()
            proc.rmdir()
    return type('Result',(),{'returncode':0,'stdout':''})()
subprocess.run=_fixture_run
`
	program := recoveryPreparationAdmissionRemote
	program = strings.ReplaceAll(program, "state=Path('/var/lib/ultra-ansible')", "state=Path("+fmtPython(f.state)+")")
	program = strings.ReplaceAll(program, "system=Path('/etc/systemd/system')", "system=Path("+fmtPython(f.system)+")")
	program = strings.ReplaceAll(program, "proc=Path('/proc')", "proc=Path("+fmtPython(f.proc)+")")
	program = strings.ReplaceAll(program, "[p]+list(p.parents)", "[p]")
	program = strings.ReplaceAll(program, "s.st_uid==0", "s.st_uid==os.geteuid()")
	// Authenticated original opened paths retain the production namespace in bytes.
	program = strings.ReplaceAll(program, "raw=trusted(match[1]).read_bytes()", "raw=trusted(state/Path(match[1]).name).read_bytes()")
	f.program = prefix + program
	return f
}

func (f recoveryAdmissionFixture) command(t *testing.T, mode string) *exec.Cmd {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip(err)
	}
	raw, _ := json.Marshal(
		map[string]any{
			"admission":           f.proof,
			"baseline_installers": map[string]string{runtime.GOARCH: digestSHA256([]byte("baseline-binary"))},
		},
	)
	return exec.Command(python, "-u", "-c", f.program, mode, "bridge", base64.StdEncoding.EncodeToString(raw))
}

func TestRecoveryPreparationAdmissionSealValidateAndRecheck(t *testing.T) {
	f := preparationAdmissionFixture(t)
	lease, err := startRecoveryPreparationAdmission(f.command(t, "seal"), "seal")
	if err != nil {
		t.Fatal(err)
	}
	if err = lease.recheck(); err != nil {
		t.Fatal(err)
	}
	lease.close()
	raw, err := os.ReadFile(filepath.Join(f.state, "recovery-preparation-admission.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got recoveryPreparationAdmission
	if json.Unmarshal(raw, &got) != nil || got != f.proof {
		t.Fatal(string(raw))
	}
	before, _ := os.ReadFile(filepath.Join(f.root, "mutations"))
	lease, err = startRecoveryPreparationAdmission(f.command(t, "validate"), "validate")
	if err != nil {
		t.Fatal(err)
	}
	if err = lease.recheck(); err != nil {
		t.Fatal(err)
	}
	lease.close()
	after, _ := os.ReadFile(filepath.Join(f.root, "mutations"))
	if string(before) != string(after) {
		t.Fatal("validation mutated origins")
	}
}

func TestRecoveryPreparationAdmissionRequiresThirdOldOperatorLock(t *testing.T) {
	f := preparationAdmissionFixture(t)
	_ = os.Remove(filepath.Join(f.state, "operator/infrastructure.lock"))
	if _, err := startRecoveryPreparationAdmission(f.command(t, "seal"), "seal"); err == nil {
		t.Fatal("missing historical operator lock admitted")
	}
	if _, err := os.Stat(filepath.Join(f.root, "mutations")); !os.IsNotExist(err) {
		t.Fatal("mutated without old operator proof")
	}
}

func TestRecoveryPreparationAdmissionLegacyFailedJobNeverDrained(t *testing.T) {
	f := preparationAdmissionFixture(t)
	job := filepath.Join(f.state, "11111111-2222-3333-4444-555555555555")
	_ = os.Mkdir(job, 0700)
	_ = os.WriteFile(filepath.Join(job, "prepared"), nil, 0600)
	_ = os.WriteFile(filepath.Join(job, "receipt.json"), []byte(`{"state":"failed"}`), 0600)
	if _, err := startRecoveryPreparationAdmission(f.command(t, "seal"), "seal"); err == nil {
		t.Fatal("ambiguous legacy job admitted")
	}
	if _, err := os.Stat(filepath.Join(f.root, "mutations")); !os.IsNotExist(err) {
		t.Fatal("stopped live origins before dispatch proof")
	}
}

func TestRecoveryPreparationAdmissionAuthenticatesIdleBrokerBeforeGracefulStop(t *testing.T) {
	f := preparationAdmissionFixture(t)
	auth, _ := json.Marshal(
		map[string]any{
			"protocol":     "ultra-retained-primary-reconcile-v1",
			"fence_sha256": f.proof.FenceSHA256,
			"artifacts":    map[string]string{"manifest": f.proof.BaselineManifestSHA256, "config": f.proof.ConfigSHA256},
		},
	)
	name := "retained-primary-controller-" + digestSHA256(auth) + ".json"
	_ = os.WriteFile(filepath.Join(f.state, name), auth, 0600)
	opened := "[Unit]\nRefuseManualStart=no\nConditionPathExists=/var/lib/ultra-ansible/" + name + "\n"
	_ = os.WriteFile(filepath.Join(f.system, "ultra-ansible-controller.service.d", "90-retained-primary.conf"), []byte(opened), 0600)
	_ = os.WriteFile(filepath.Join(f.root, "active"), nil, 0600)
	process := filepath.Join(f.proc, "4242")
	_ = os.Mkdir(process, 0700)
	_ = os.WriteFile(
		filepath.Join(process, "cmdline"),
		[]byte(
			"/opt/ultra-ansible/releases/v1.2.3/ultra-install\x00ansible-controller\x00--executable\x00/opt/ultra-ansible/releases/v1.2.3/venv/bin/ansible-playbook\x00",
		),
		0600,
	)
	_ = os.WriteFile(filepath.Join(process, "exe"), []byte("baseline-binary"), 0600)
	lease, err := startRecoveryPreparationAdmission(f.command(t, "seal"), "seal")
	if err != nil {
		t.Fatal(err)
	}
	lease.close()
	if _, err = os.Stat(filepath.Join(f.root, "active")); !os.IsNotExist(err) {
		t.Fatal("idle broker still active")
	}
}

func TestRecoveryPreparationAdmissionLeaseDeathFailsRecheck(t *testing.T) {
	f := preparationAdmissionFixture(t)
	lease, err := startRecoveryPreparationAdmission(f.command(t, "seal"), "seal")
	if err != nil {
		t.Fatal(err)
	}
	_ = lease.command.Process.Kill()
	select {
	case <-lease.done:
	case <-time.After(time.Second):
		t.Fatal("lease death not observed")
	}
	if lease.recheck() == nil {
		t.Fatal("dead session accepted")
	}
	lease.close()
}

func TestRecoveryPreparationAdmissionRejectsChangedBindingAndNewFence(t *testing.T) {
	f := preparationAdmissionFixture(t)
	lease, err := startRecoveryPreparationAdmission(f.command(t, "seal"), "seal")
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(f.state, "execution-fence.json"), []byte(`{}`), 0600)
	if lease.recheck() == nil {
		t.Fatal("new uncertain executor fence ignored")
	}
	lease.close()
	_ = os.Remove(filepath.Join(f.state, "execution-fence.json"))
	original, _ := os.ReadFile(filepath.Join(f.state, "recovery-preparation-admission.json"))
	altered := f.proof
	altered.ConfigSHA256 = strings.Repeat("e", 64)
	raw, _ := json.Marshal(altered)
	_ = os.WriteFile(filepath.Join(f.state, "recovery-preparation-admission.json"), raw, 0600)
	if _, err = startRecoveryPreparationAdmission(f.command(t, "seal"), "seal"); err == nil {
		t.Fatal("mismatched binding overwritten")
	}
	after, _ := os.ReadFile(filepath.Join(f.state, "recovery-preparation-admission.json"))
	if string(after) != string(raw) || string(after) == string(original) {
		t.Fatal("changed original admission")
	}
}

func TestRecoveryPreparationAdmissionDrainsOnlyExactBrokerCommand(t *testing.T) {
	f := preparationAdmissionFixture(t)
	_ = os.WriteFile(filepath.Join(f.root, "active"), nil, 0600)
	process := filepath.Join(f.proc, "4242")
	_ = os.Mkdir(process, 0700)
	_ = os.WriteFile(filepath.Join(process, "cmdline"), []byte("ultra-install\x00ansible-controller\x00--unexpected\x00"), 0600)
	_ = os.WriteFile(filepath.Join(process, "exe"), []byte("baseline-binary"), 0600)
	if _, err := startRecoveryPreparationAdmission(f.command(t, "seal"), "seal"); err == nil {
		t.Fatal("unrecognized broker command stopped")
	}
	if _, err := os.Stat(filepath.Join(f.root, "mutations")); !os.IsNotExist(err) {
		t.Fatal("mutated before authenticated idle broker proof")
	}
}

// The supervisor is excluded separately as local_invoker. Its start waiter is
// admitted only with a root-owned descriptor binding this exact process image,
// argv, creation time and immutable schema2 operation. A foreign waiter is live.
func TestRecoveryPreparationAdmissionExactObserver(t *testing.T) {
	for _, changed := range []string{"", "argv", "starttime", "foreign", "candidate", "request"} {
		t.Run(changed, func(t *testing.T) {
			f := preparationAdmissionFixture(t)
			write := func(p string, v any) {
				t.Helper()
				b, _ := json.Marshal(v)
				if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(p, b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			commit := strings.Repeat("1", 40)
			version := "v0.0.97433442488726861213578988847752201310395502865"
			release := filepath.Join(f.state, "operator-inputs", "manual-"+commit+"-"+strings.Repeat("2", 64), "release")
			binary := []byte("candidate-binary")
			manifest := map[string]any{
				"source_commit": commit,
				"version":       version,
				"assets": []any{
					map[string]any{"name": "ultra-install-linux-" + runtime.GOARCH, "size": len(binary), "sha256": digestSHA256(binary)},
				},
			}
			write(filepath.Join(release, "release-manifest.json"), manifest)
			_ = os.WriteFile(filepath.Join(release, "ultra-install-linux-"+runtime.GOARCH), binary, 0600)
			manifestRaw, _ := os.ReadFile(filepath.Join(release, "release-manifest.json"))
			retained := filepath.Join(filepath.Dir(release), "preparation", "retained")
			prep := map[string]any{
				"retained_directory":       retained,
				"tools_release_directory":  release,
				"tools_manifest_sha256":    digestSHA256(manifestRaw),
				"retained_fence_sha256":    f.proof.FenceSHA256,
				"baseline_manifest_sha256": f.proof.BaselineManifestSHA256,
				"config_sha256":            f.proof.ConfigSHA256,
			}
			prepPath := filepath.Join(filepath.Dir(retained), "preparation.json")
			write(prepPath, prep)
			prepRaw, _ := os.ReadFile(prepPath)
			args := []string{"operator-upgrade", "--source-commit", commit, "--version", version}
			request := map[string]any{"schema": 2, "args": args, "preparation": prep}
			requestRaw, _ := json.Marshal(request)
			sha := digestSHA256(requestRaw)
			op := filepath.Join(f.state, "deploy-operations", sha)
			write(filepath.Join(op, "request.json"), request)
			write(filepath.Join(f.state, "deploy-operations", "current.json"), map[string]any{"schema": 1, "request_sha256": sha})
			write(
				filepath.Join(op, "state.json"),
				map[string]any{"schema": 1, "request_sha256": sha, "state": "running", "stage": "origins_sealed"},
			)
			process := filepath.Join(f.proc, "4243")
			_ = os.MkdirAll(process, 0700)
			command := []byte(
				strings.Join(
					append(
						[]string{
							release + "/ultra-install-linux-" + runtime.GOARCH,
							"deploy-operation",
							"start",
							"--preparation-file",
							prepPath,
							"--preparation-sha256",
							digestSHA256(prepRaw),
							"--",
						},
						args...),
					"\x00",
				) + "\x00",
			)
			_ = os.WriteFile(filepath.Join(process, "cmdline"), command, 0600)
			_ = os.WriteFile(filepath.Join(process, "exe"), binary, 0600)
			start := "12345"
			_ = os.WriteFile(filepath.Join(process, "stat"), []byte("4243 (ultra-install) S "+strings.Repeat("0 ", 18)+start+" 0"), 0600)
			write(
				filepath.Join(op, "observers", "4243-"+start+".json"),
				map[string]any{
					"schema":            1,
					"request_sha256":    sha,
					"pid":               4243,
					"starttime":         start,
					"executable_sha256": digestSHA256(binary),
					"argv_sha256":       digestSHA256(command),
				},
			)
			switch changed {
			case "argv":
				_ = os.WriteFile(filepath.Join(process, "cmdline"), append(command, []byte("operator-upgrade\x00")...), 0600)
			case "starttime":
				_ = os.WriteFile(filepath.Join(process, "stat"), []byte("4243 (ultra-install) S "+strings.Repeat("0 ", 18)+"12346 0"), 0600)
			case "candidate":
				_ = os.WriteFile(filepath.Join(process, "exe"), []byte("other-binary"), 0600)
			case "request":
				_ = os.WriteFile(filepath.Join(op, "request.json"), []byte(`{}`), 0600)
			case "foreign":
				foreign := filepath.Join(f.proc, "4244")
				_ = os.Mkdir(foreign, 0700)
				_ = os.WriteFile(filepath.Join(foreign, "cmdline"), command, 0600)
			}
			lease, e := startRecoveryPreparationAdmission(f.command(t, "seal"), "seal")
			if changed == "" {
				if e != nil {
					t.Fatal(e)
				}
				lease.close()
			} else if e == nil {
				lease.close()
				t.Fatal(fmt.Sprint("foreign process admitted: ", changed))
			}
		})
	}
}
