package main

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestRetainedCredentialsRequireStablePrivateIdentity(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "saved.json")
	p := &installplan.InstallPlan{Database: installplan.DatabaseConfig{Name: "fixture", User: "app"}}
	if _, err := retainedExistingDatabaseCredentials(p); err == nil {
		t.Fatal("missing credentials would permit random password generation")
	}
	p.Secrets.DatabaseCredentialsFile = path
	for _, dsn := range []string{"postgres://app:fixture@127.0.0.1:25432/fixture", "postgres://wrong:fixture@127.0.0.1:25432/fixture", "postgres://app@127.0.0.1:25432/fixture", "postgres://app:fixture@192.0.2.1:5432/fixture"} {
		raw, _ := json.Marshal(map[string]any{"database": map[string]string{"dsn": dsn}})
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := retainedExistingDatabaseCredentials(p)
		if dsn == "postgres://app:fixture@127.0.0.1:25432/fixture" {
			if err != nil || got != dsn {
				t.Fatal("stable credentials rejected")
			}
		} else if err == nil {
			t.Fatal("invalid identity accepted")
		}
	}
	if err := os.WriteFile(path, []byte(`{"database":{"dsn":"postgres://app:fixture@127.0.0.1:25432/fixture"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := retainedExistingDatabaseCredentials(p); err == nil {
		t.Fatal("public credentials accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := retainedExistingDatabaseCredentials(p); err == nil {
		t.Fatal("absent saved credentials accepted")
	}
}

func TestRetainedAdmissionRejectsOrphanReplayAndTerminalReceipt(t *testing.T) {
	directory := t.TempDir()
	state := filepath.Join(directory, "state")
	// Exercise the real lease program with only paths, UID and systemctl replaced.
	// Killing this process models a lost SSH lease while its Ansible child survives.
	lease := strings.ReplaceAll(retainedFenceLease, "/var/lib/ultra-ansible", state)
	lease = strings.ReplaceAll(lease, "/etc/systemd/system", filepath.Join(directory, "systemd"))
	lease = strings.ReplaceAll(lease, ".st_uid==0", ".st_uid==os.geteuid()")
	lease = "import subprocess,types\nsubprocess.run=lambda *a,**k:types.SimpleNamespace(stdout='not-found',returncode=0)\n" + lease
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-u", "-c", lease, "first-attempt")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = input.Close() }()
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	scanner := bufio.NewScanner(output)
	if !scanner.Scan() || scanner.Text() != "ready" {
		_ = cmd.Wait()
		t.Fatalf("first admission failed: %s", stderr.String())
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("expected crash")
	}
	marker := filepath.Join(state, "retained-primary-admission.json")
	before, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	// A claimed successful receipt cannot bypass independent executor drain.
	if err := os.WriteFile(filepath.Join(state, "terminal-receipt.json"), []byte(`{"state":"succeeded"}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, binding := range []string{"first-attempt", "new-workspace-attempt"} {
		run := exec.CommandContext(ctx, "python3", "-u", "-c", lease, binding)
		if out, err := run.CombinedOutput(); err == nil || strings.Contains(string(out), "ready") {
			t.Fatal("orphan/terminal replay admitted")
		}
	}
	check := strings.ReplaceAll(retainedFenceAdmissionCheck, "/var/lib/ultra-ansible", state)
	if err := exec.CommandContext(ctx, "python3", "-c", check).Run(); err == nil {
		t.Fatal("preflight accepted existing marker")
	}
	after, err := os.ReadFile(marker)
	if err != nil || string(before) != string(after) {
		t.Fatal("marker overwritten")
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(directory, "absent"), marker); err != nil {
		t.Fatal(err)
	}
	if err := exec.CommandContext(ctx, "python3", "-c", check).Run(); err == nil {
		t.Fatal("dangling marker symlink admitted")
	}
}

func TestRetainedCLIRequiresExplicitScopeBeforeInputAccess(t *testing.T) {
	for _, args := range [][]string{nil, {"--prepare-only"}, {"--accept-reimaged-fleet"}, {"--accept-reimaged-fleet", "--config", "relative"}} {
		if err := runRetainedPrimaryCommand(args); err == nil {
			t.Fatal("accepted incomplete scope")
		}
	}
}
func TestRetainedFenceProgramsCompileAndRequireDurableAdmission(t *testing.T) {
	for name, program := range map[string]string{"lease": retainedFenceLease, "verify": retainedFenceVerify} {
		command := exec.Command("python3", "-c", "import sys; compile(sys.stdin.read(),'<fence>','exec')")
		command.Stdin = strings.NewReader(program)
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v %s", name, err, out)
		}
		for _, needed := range []string{"retained-primary-admission", "RefuseManualStart", "ConditionPathExists"} {
			if !strings.Contains(program, needed) {
				t.Fatalf("%s missing %s", name, needed)
			}
		}
	}
	if !strings.Contains(retainedFenceLease, "LOCK_EX|fcntl.LOCK_NB") || !strings.Contains(retainedFenceVerify, "/proc") {
		t.Fatal("missing lock or process verification")
	}
}
func TestRetainedBackupRejectsUnauthenticatedInputs(t *testing.T) {
	p := filepath.Join(t.TempDir(), "backup.age")
	if err := os.WriteFile(p, []byte("not an archive"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyRetainedBackup(p, strings.Repeat("0", 64), "/private/identity"); err == nil {
		t.Fatal("accepted changed backup")
	}
	if err := os.Chmod(p, 0644); err != nil {
		t.Fatal(err)
	}
	if err := verifyRetainedBackup(p, strings.Repeat("0", 64), "/private/identity"); err == nil {
		t.Fatal("accepted public backup")
	}
}

func TestRetainedRouteIdentityRejectsAmbiguityAndTrustChange(t *testing.T) {
	p := &installplan.InstallPlan{
		Exits:    []installplan.ExitNode{{DialAddr: "192.0.2.2", Port: 51001}},
		Features: installplan.FeatureConfig{MainExitDomain: "tunnel.example.net"},
	}
	route := exits.BootstrapEntry{
		Address:    "192.0.2.2",
		Port:       51001,
		TunnelUUID: "5742a931-38e1-4a59-b9ac-b606d07caf2b",
		Enabled:    exits.BootstrapEnabledPtr(true),
	}
	if got, err := validateRetainedRoute(p, []exits.BootstrapEntry{route}); err != nil || got.TunnelUUID != route.TunnelUUID {
		t.Fatal("lost saved identity", err)
	}
	for _, kind := range []string{"absent", "duplicate", "address", "port", "disabled", "uuid", "pin"} {
		bad := route
		rows := []exits.BootstrapEntry{bad}
		switch kind {
		case "absent":
			rows = nil
		case "duplicate":
			rows = append(rows, bad)
		case "address":
			rows[0].Address = "192.0.2.3"
		case "port":
			rows[0].Port = 443
		case "disabled":
			rows[0].Enabled = exits.BootstrapEnabledPtr(false)
		case "uuid":
			rows[0].TunnelUUID = "invalid"
		case "pin":
			rows[0].PinnedPeerCertSHA256 = strings.Repeat("a", 64)
		}
		if _, err := validateRetainedRoute(p, rows); err == nil {
			t.Fatal("accepted " + kind)
		}
	}
}

func TestRetainedProxyCommandPreservesPinnedArgv(t *testing.T) {
	p := &installplan.InstallPlan{
		SSH:        installplan.SSHConfig{User: "root"},
		Bridge:     installplan.BridgeConfig{SSHHost: "192.0.2.1", SSHIdentity: "/private/key with 'quote"},
		Automation: &installplan.AutomationConfig{KnownHostsFile: "/private/pins with 'quote"},
	}
	proxy := retainedProxyCommand(p)
	common := "-o " + shellQuote("ProxyCommand="+proxy)
	command := exec.Command(
		"python3",
		"-c",
		`import json,shlex,sys; a=shlex.split(sys.argv[1]); print(json.dumps(shlex.split(a[1].split('=',1)[1])))`,
		common,
	)
	raw, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	if err = json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	want := retainedSSH(p, p.Bridge.SSHHost, p.BridgeSSHIdentity(), false, false)
	want = append(want, "-W", "%h:%p", "root@192.0.2.1")
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatal("proxy tokenization changed pinned argv")
	}
	if got[len(got)-3] != "-W" {
		t.Fatal("forwarding option must precede destination")
	}
	direct := retainedSSH(p, "192.0.2.3", "/private/database-key", true, true)
	found := false
	for _, arg := range direct {
		if arg == "ProxyCommand="+proxy {
			found = true
		}
	}
	if !found {
		t.Fatal("Ansible and direct collector must share the proxy")
	}
}
