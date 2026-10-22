package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func managedPreparationFixture(t *testing.T) (recoveryAdmissionFixture, string, string, string) {
	t.Helper()
	f := preparationAdmissionFixture(t)
	base := filepath.Join(f.root, "automation")
	directory := filepath.Join(base, "releases", "managed-v0.0.1")
	release := filepath.Join(f.state, "operator-inputs", "manual-"+strings.Repeat("0", 39)+"1-"+strings.Repeat("a", 64), "release")
	write := func(path string, raw []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	binary := []byte("independent-managed-installer")
	runtimeRaw := []byte("runtime archive")
	runtimeSHA := digestSHA256(runtimeRaw)
	write(filepath.Join(directory, "ultra-install"), binary)
	if err := os.Chmod(filepath.Join(directory, "ultra-install"), 0700); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(directory, "runtime.sha256"), []byte(runtimeSHA+"\n"))
	write(filepath.Join(directory, "venv", "bin", "ansible-playbook"), []byte("retained playbook"))
	if err := os.Symlink(directory, filepath.Join(base, "current")); err != nil {
		t.Fatal(err)
	}
	assets := []map[string]any{}
	for name, raw := range map[string][]byte{"ultra-install-linux-" + runtime.GOARCH: binary, "ultra-ansible-runtime-linux-" + runtime.GOARCH + ".tar.gz": runtimeRaw} {
		write(filepath.Join(release, name), raw)
		assets = append(assets, map[string]any{"name": name, "size": len(raw), "sha256": digestSHA256(raw)})
	}
	manifest := filepath.Join(release, "release-manifest.json")
	raw, _ := json.Marshal(
		map[string]any{"schema_version": 1, "version": "v0.0.1", "source_commit": strings.Repeat("0", 39) + "1", "assets": assets},
	)
	write(manifest, raw)
	inventory := map[string]any{}
	if err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == directory {
			return nil
		}
		rel, _ := filepath.Rel(directory, path)
		if entry.IsDir() {
			inventory[rel] = []any{"directory", 0700}
		} else {
			content, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			info, e := entry.Info()
			if e != nil {
				return e
			}
			inventory[rel] = []any{"file", digestSHA256(content), int(info.Mode().Perm())}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	receipt := filepath.Join(f.state, "retention", digestSHA256([]byte(directory))+".json")
	raw, _ = json.Marshal(
		map[string]any{
			"schema": 1,
			"path":   directory,
			"identity": map[string]string{
				"ultra-install":  digestSHA256(binary),
				"runtime.sha256": digestSHA256([]byte(runtimeSHA + "\n")),
			},
			"inventory": inventory,
		},
	)
	write(receipt, raw)
	process := filepath.Join(f.proc, "4242")
	argv := []string{
		filepath.Join(directory, "ultra-install"),
		"ansible-controller",
		"--executable",
		filepath.Join(directory, "venv/bin/ansible-playbook"),
	}
	write(filepath.Join(process, "cmdline"), []byte(strings.Join(argv, "\x00")+"\x00"))
	if err := os.Symlink(argv[0], filepath.Join(process, "exe")); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(process, "status"), []byte("Uid:\t0 0 0 0\nGid:\t0 0 0 0\n"))
	write(filepath.Join(process, "stat"), []byte("4242 (ultra-install) S 1"+strings.Repeat(" 0", 17)+" 123"))
	write(filepath.Join(process, "cgroup"), []byte("0::/system.slice/ultra-ansible-controller.service\n"))
	write(filepath.Join(f.root, "active"), nil)
	unit := filepath.Join(f.system, "ultra-ansible-controller.service")
	write(unit, []byte("[Service]\nUser=root\nGroup=root\nKillMode=control-group\nExecStart="+strings.Join(argv, " ")+"\n"))
	write(
		filepath.Join(f.root, "properties"),
		[]byte(
			fmt.Sprintf(
				"Id=ultra-ansible-controller.service\nSubState=running\nFragmentPath=%s\nControlGroup=/system.slice/ultra-ansible-controller.service\nUser=root\nGroup=root\nDropInPaths=%s.d/90-retained-primary.conf\n",
				unit,
				unit,
			),
		),
	)
	f.program = strings.ReplaceAll(f.program, "/opt/ultra-ansible", base)
	f.program = strings.ReplaceAll(f.program, "current.lstat().st_uid==0", "current.lstat().st_uid==os.geteuid()")
	return f, directory, manifest, receipt
}

func TestRecoveryPreparationManagedController(t *testing.T) {
	for _, kind := range []string{"valid", "manifest-version", "manifest-digest", "receipt-identity", "pending", "inventory", "marker", "executable", "unrelated", "dropin", "service", "exec-stop", "exec-stop-post", "metadata", "symlink", "replacement-before-stop"} {
		t.Run(kind, func(t *testing.T) {
			f, directory, manifest, receipt := managedPreparationFixture(t)
			mutate := func(path string, change func(map[string]any)) {
				t.Helper()
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var value map[string]any
				if err = json.Unmarshal(raw, &value); err != nil {
					t.Fatal(err)
				}
				change(value)
				raw, _ = json.Marshal(value)
				if err = os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "manifest-version":
				mutate(manifest, func(v map[string]any) { v["version"] = "v0.0.2" })
			case "manifest-digest":
				mutate(manifest, func(v map[string]any) { v["assets"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("0", 64) })
			case "receipt-identity":
				mutate(receipt, func(v map[string]any) { v["identity"].(map[string]any)["ultra-install"] = strings.Repeat("0", 64) })
			case "pending":
				mutate(receipt, func(v map[string]any) { v["pending"] = true })
			case "inventory":
				_ = os.WriteFile(filepath.Join(directory, "extra"), []byte("unknown"), 0600)
			case "marker":
				_ = os.WriteFile(filepath.Join(directory, "runtime.sha256"), []byte(strings.Repeat("0", 64)+"\n"), 0600)
			case "executable":
				_ = os.Remove(filepath.Join(f.proc, "4242/exe"))
				_ = os.WriteFile(filepath.Join(f.proc, "4242/exe"), []byte("foreign"), 0600)
			case "unrelated":
				_ = os.Mkdir(filepath.Join(f.proc, "9999"), 0700)
				_ = os.WriteFile(filepath.Join(f.proc, "9999/cmdline"), []byte("/foreign/ultra-install\x00operator-upgrade\x00"), 0600)
			case "dropin":
				path := filepath.Join(f.root, "properties")
				raw, _ := os.ReadFile(path)
				_ = os.WriteFile(path, []byte(strings.ReplaceAll(string(raw), "DropInPaths=", "DropInPaths=/foreign.conf ")), 0600)
			case "service":
				_ = os.WriteFile(filepath.Join(f.proc, "4242/cgroup"), []byte("0::/other.service\n"), 0600)
			case "exec-stop", "exec-stop-post":
				path := filepath.Join(f.system, "ultra-ansible-controller.service")
				raw, _ := os.ReadFile(path)
				hook := "ExecStop=/bin/false\n"
				if kind == "exec-stop-post" {
					hook = "ExecStopPost=/bin/false\n"
				}
				_ = os.WriteFile(path, append(raw, []byte(hook)...), 0600)
			case "metadata":
				_ = os.Chmod(receipt, 0644)
			case "symlink":
				raw, _ := os.ReadFile(receipt)
				_ = os.WriteFile(receipt+".copy", raw, 0600)
				_ = os.Remove(receipt)
				_ = os.Symlink(receipt+".copy", receipt)
			case "replacement-before-stop":
				f.program = strings.Replace(
					f.program,
					"    with (_fixture_root/'mutations').open",
					"    if args[1]=='daemon-reload':\n        path=_fixture_root/'proc/4242/stat'\n        path.write_text(path.read_text().replace(' 123',' 124'))\n    with (_fixture_root/'mutations').open",
					1,
				)
			}
			lease, err := startRecoveryPreparationAdmission(f.command(t, "seal"), "seal")
			if kind == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				lease.close()
				if _, err = os.Stat(filepath.Join(f.root, "active")); !os.IsNotExist(err) {
					t.Fatal("controller not stopped")
				}
				return
			}
			if err == nil {
				lease.close()
				t.Fatal("unverified controller admitted")
			}
			if kind == "replacement-before-stop" {
				raw, _ := os.ReadFile(filepath.Join(f.root, "mutations"))
				if strings.Contains(string(raw), `"stop"`) {
					t.Fatal("stopped replacement process")
				}
				return
			}
			if _, err = os.Stat(filepath.Join(f.root, "mutations")); !os.IsNotExist(err) {
				t.Fatal("mutated before authentication")
			}
		})
	}
}
