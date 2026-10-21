package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	ansibleassets "github.com/NikitaDmitryuk/ultra/deploy/ansible"
)

func cloudRuntimeFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, directory := range []string{"etc/systemd/system", "var/lib/ultra-relay/automation", "usr/local/bin"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "usr/local/bin/ultra-relay"), []byte("fixture-relay"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/systemd/system/ultra-relay.service"), []byte("fixture-unit"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "var/lib/ultra-relay/automation/vultr-api-key"), []byte("synthetic-test-only"), 0600); err != nil {
		t.Fatal(err)
	}
	return root
}

func runCloudRuntimeFixture(t *testing.T, root string, preflight bool) error {
	return runCloudRuntimeFixtureDrift(t, root, preflight, "")
}

func runCloudRuntimeFixtureDrift(t *testing.T, root string, preflight bool, drift string) error {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	if _, err = exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen unavailable")
	}
	program := strings.NewReplacer(
		"cloud_root_uid = 0", fmt.Sprintf("cloud_root_uid = %d", os.Getuid()),
		"cloud_root_gid = 0", fmt.Sprintf("cloud_root_gid = %d", os.Getgid()),
		"cloud_account = pwd.getpwnam('ultra-relay')", fmt.Sprintf("cloud_account = type('Account',(),{'pw_uid':%d})()", os.Getuid()),
		"cloud_group = grp.getgrnam('ultra-relay').gr_gid", fmt.Sprintf("cloud_group = %d", os.Getgid()),
		"/etc", filepath.Join(root, "etc"),
		"/var", filepath.Join(root, "var"),
		"/usr", filepath.Join(root, "usr"),
	).Replace(retainedReconcileCloudProgram)
	prelude := fmt.Sprintf(`import subprocess,os
cloud_bridge_ipv4='192.0.2.10'
cloud_preflight_only=%s
cloud_expected_relay_sha256='%x'
cloud_expected_unit_sha256='%x'
drift_path=%q
real_run=subprocess.run
def fake_run(args,**kwargs):
 if args[0]=='runuser':return subprocess.CompletedProcess(args,0 if os.access(args[-1],os.R_OK) else 1)
 if args[0]=='systemctl':
  if args[1]=='show':
   return subprocess.CompletedProcess(args,0,stdout='FragmentPath='+%q+'\nExecStart={ path='+%q+' ; argv[]='+%q+' -require-provider-pool-quota -spec '+%q+' ; ignore_errors=no ; }\n')
  if args[1]=='daemon-reload' and drift_path:
   with open(drift_path,'w') as f:f.write('changed after preflight')
  with open(%q,'a') as f:f.write(' '.join(args)+'\n')
  return subprocess.CompletedProcess(args,0)
 return real_run(args,**kwargs)
subprocess.run=fake_run
`, map[bool]string{true: "True", false: "False"}[preflight], sha256.Sum256([]byte("fixture-relay")), sha256.Sum256([]byte("fixture-unit")), drift, filepath.Join(root, "etc/systemd/system/ultra-relay.service"), filepath.Join(root, "usr/local/bin/ultra-relay"), filepath.Join(root, "usr/local/bin/ultra-relay"), filepath.Join(root, "etc/ultra-relay/spec.json"), filepath.Join(root, "systemctl-calls"))
	output, err := exec.Command(python, "-c", prelude+program).CombinedOutput()
	if err != nil {
		return fmt.Errorf("runtime fixture: %w: %s", err, output)
	}
	return nil
}

func TestRetainedCloudRuntimeRechecksImageBeforeRestart(t *testing.T) {
	for _, name := range []string{"usr/local/bin/ultra-relay", "etc/systemd/system/ultra-relay.service"} {
		t.Run(filepath.Base(name), func(t *testing.T) {
			root := cloudRuntimeFixture(t)
			if err := runCloudRuntimeFixtureDrift(t, root, false, filepath.Join(root, name)); err == nil {
				t.Fatal("late runtime image drift accepted")
			}
			calls, _ := os.ReadFile(filepath.Join(root, "systemctl-calls"))
			if strings.Contains(string(calls), "systemctl restart") {
				t.Fatal("changed runtime was restarted")
			}
		})
	}
}

func TestRetainedCloudRuntimePreflightAndReplay(t *testing.T) {
	root := cloudRuntimeFixture(t)
	if err := runCloudRuntimeFixture(t, root, true); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"etc/ultra-fleet", "etc/systemd/system/ultra-relay.service.d", "systemctl-calls"} {
		if _, err := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatalf("preflight mutated %s", name)
		}
	}
	if err := runCloudRuntimeFixture(t, root, false); err != nil {
		t.Fatal(err)
	}
	template, err := ansibleassets.Bundle.ReadFile("roles/upgrade_provider/templates/provider.conf.j2")
	if err != nil {
		t.Fatal(err)
	}
	expected := strings.NewReplacer(
		"{{ ultra_upgrade_provider_bridge_ipv4 }}", "192.0.2.10",
		"/var", filepath.Join(root, "var"),
		"/etc", filepath.Join(root, "etc"),
	).Replace(string(template))
	dropin, err := os.ReadFile(filepath.Join(root, "etc/systemd/system/ultra-relay.service.d/provider.conf"))
	if err != nil || string(dropin) != expected {
		t.Fatal("reconciliation provider settings diverge from the managed Ansible role")
	}
	key := filepath.Join(root, "etc/ultra-fleet/id_ed25519")
	before, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	if err = runCloudRuntimeFixture(t, root, false); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(key)
	if err != nil || string(before) != string(after) {
		t.Fatal("runtime replay rotated fleet identity")
	}
	info, err := os.Stat(key)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("fleet private identity is not private")
	}
	calls, err := os.ReadFile(filepath.Join(root, "systemctl-calls"))
	if err != nil || strings.Count(string(calls), "systemctl restart ultra-relay.service") != 2 {
		t.Fatalf("unexpected activation calls: %s, %v", calls, err)
	}
}

func TestRetainedCloudRuntimeRejectsUnsafeExistingState(t *testing.T) {
	for _, scenario := range []string{"missing_key", "linked_key", "writable_fleet", "different_dropin", "mismatched_public_key", "staged_binary", "staged_unit", "staged_execstart"} {
		t.Run(scenario, func(t *testing.T) {
			root := cloudRuntimeFixture(t)
			key := filepath.Join(root, "var/lib/ultra-relay/automation/vultr-api-key")
			switch scenario {
			case "staged_binary":
				_ = os.WriteFile(filepath.Join(root, "usr/local/bin/ultra-relay"), []byte("candidate-with-new-migrations"), 0755)
			case "staged_unit":
				_ = os.WriteFile(filepath.Join(root, "etc/systemd/system/ultra-relay.service"), []byte("ExecStart=/elsewhere"), 0644)
			case "staged_execstart":
				p := filepath.Join(root, "etc/systemd/system/ultra-relay.service.d")
				_ = os.Mkdir(p, 0755)
				_ = os.WriteFile(filepath.Join(p, "other.conf"), []byte("[Service]\nExecStart=/elsewhere\n"), 0644)
			case "missing_key":
				if err := os.Remove(key); err != nil {
					t.Fatal(err)
				}
			case "linked_key":
				if err := os.Rename(key, key+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(key+".saved", key); err != nil {
					t.Fatal(err)
				}
			case "writable_fleet":
				dir := filepath.Join(root, "etc/ultra-fleet")
				if err := os.Mkdir(dir, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(dir, 0777); err != nil {
					t.Fatal(err)
				}
			case "different_dropin":
				dir := filepath.Join(root, "etc/systemd/system/ultra-relay.service.d")
				if err := os.Mkdir(dir, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "provider.conf"), []byte("operator-owned config\n"), 0644); err != nil {
					t.Fatal(err)
				}
			case "mismatched_public_key":
				if err := runCloudRuntimeFixture(t, root, false); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(root, "systemctl-calls")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "etc/ultra-fleet/id_ed25519.pub"), []byte("ssh-ed25519 different"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if err := runCloudRuntimeFixture(t, root, false); err == nil {
				t.Fatal("unsafe input accepted")
			}
			if _, err := os.Stat(filepath.Join(root, "systemctl-calls")); !os.IsNotExist(err) {
				t.Fatal("unsafe input reached service mutation")
			}
		})
	}
}
