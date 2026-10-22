package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestUpgradeV3ProjectedConfigLoadsRealLifecycleInventory(t *testing.T) {
	config, original := lifecycleCLIFixture(t)
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	program := `import importlib.util,sys
spec=importlib.util.spec_from_file_location('manual_deploy',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
sys.stdout.buffer.write(m.projected_upgrade_config(sys.stdin.buffer.read(),'upgrade-v3'))`
	cmd := exec.Command("python3", "-c", program, filepath.Join(root, "scripts/manual-deploy.py"))
	cmd.Stdin = bytes.NewReader(
		append(
			original,
			[]byte(
				"SSH_USER=operator\nBRIDGE_SSH_KEY=/home/operator/bridge\nMAIN_EXIT_SSH_KEY=/home/operator/exit\nDATABASE_SSH_KEY=/home/operator/db\n",
			)...),
	)
	projected, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("projection: %s %v", projected, err)
	}
	if bytes.Contains(projected, []byte("/home/operator")) {
		t.Fatal("operator path leaked")
	}
	if err = os.WriteFile(config, projected, 0600); err != nil {
		t.Fatal(err)
	}
	p, err := installplan.LoadLifecycleConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if p.BridgeSSHIdentity() != installedFleetIdentity || p.Database.SSHIdentity != installedFleetIdentity || p.SSH.User != "root" {
		t.Fatalf("projection did not survive real lifecycle loader: %+v", p.SSH)
	}
	// Only physical machine/filesystem attestation is substituted. The Python
	// projection, Go loader and actual inventory constructor remain production code.
	pins := filepath.Join(t.TempDir(), "known_hosts")
	if err = os.WriteFile(pins, []byte("fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	previous := attestInstalledRuntimeTransport
	t.Cleanup(func() { attestInstalledRuntimeTransport = previous })
	called := false
	attestInstalledRuntimeTransport = func(plan *installplan.InstallPlan) error {
		called = true
		if plan.Automation.KnownHostsFile != "/etc/ultra-recovery/known_hosts" || plan.Database.SSHUser != "root" {
			t.Fatal("fixed transport changed")
		}
		plan.Automation.KnownHostsFile = pins
		return nil
	}
	local := true
	p.ControllerLocal, p.ControllerLocalTarget = &local, p.Bridge.SSHHost+"|"+p.Bridge.Address
	inventory, err := bootstrapInventory(p, t.TempDir())
	if err != nil || !called {
		t.Fatal("inventory did not attest projected transport", err)
	}
	raw, _ := json.Marshal(inventory)
	if bytes.Contains(raw, []byte("/home/operator")) || !bytes.Contains(raw, []byte(installedFleetIdentity)) ||
		bytes.Contains(raw, []byte(`"ansible_user":"operator"`)) {
		t.Fatalf("incorrect transport inventory: %s", raw)
	}
	attestInstalledRuntimeTransport = func(*installplan.InstallPlan) error { return errors.New("fixture_identity_rejected") }
	if _, err = bootstrapInventory(p, t.TempDir()); err == nil || err.Error() != "fixture_identity_rejected" {
		t.Fatal("attestation bypassed", err)
	}
	if err = previous(p); err == nil {
		t.Fatal("non-bridge fixture accepted by physical attestation")
	}
}

func TestUpgradeCLIExecutionContextPreservesLegacyAncillaryRequests(t *testing.T) {
	for _, args := range [][]string{nil, {"--execution-timeout=2h"}, {"--execution-timeout=1h"}} {
		t.Run(strings.Join(args, ""), func(t *testing.T) {
			fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
			timeout := fs.Duration("execution-timeout", time.Hour, "")
			if err := fs.Parse(args); err != nil {
				t.Fatal(err)
			}
			ctx, err := upgradeExecutionContext(context.Background(), fs, *timeout)
			if err != nil {
				t.Fatal(err)
			}
			legacy := []byte(`{"inventory":{},"variables":{}}`)
			for _, operation := range []string{"inspect-upgrade", "lifecycle", "prepare-controller", "upgrade", "wait-upgrade-readiness"} {
				directory := t.TempDir()
				if err = os.WriteFile(filepath.Join(directory, "request.json"), legacy, 0600); err != nil {
					t.Fatal(err)
				}
				raw, err := deployansible.LocalRequestBytes(ctx, operation, directory, map[string]any{}, map[string]any{})
				if err != nil {
					t.Fatal(err)
				}
				changed := operation == "upgrade" && len(args) > 0
				if bytes.Equal(raw, legacy) == changed {
					t.Fatalf("%s explicit=%v: %s", operation, len(args) > 0, raw)
				}
				fresh, err := deployansible.LocalRequestBytes(
					ctx,
					operation,
					filepath.Join(directory, "fresh"),
					map[string]any{},
					map[string]any{},
				)
				if err != nil {
					t.Fatal(err)
				}
				var request map[string]any
				if json.Unmarshal(fresh, &request) != nil {
					t.Fatal("bad request")
				}
				want := float64(1200)
				if operation == "upgrade" {
					want = timeout.Seconds()
				}
				if operation == "wait-upgrade-readiness" {
					want = 700
				}
				if request["execution_timeout_seconds"] != want {
					t.Fatalf("%s: %s want %v", operation, fresh, want)
				}
			}
		})
	}
}
