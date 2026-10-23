package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	ansibleassets "github.com/NikitaDmitryuk/ultra/deploy/ansible"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/install"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestPreservedPrimaryDesiredExcludesProvisioningAndPreservesCredentials(t *testing.T) {
	p, ds, inv, inspection := dependencyFixture(t)
	p.Database = installplan.DatabaseConfig{Enabled: true, Name: "fixture", User: "app", PrimaryHost: "192.0.2.40"}
	p.SourceValues = map[string]string{preservePrimarySourceKey: strings.Repeat("a", 64)}
	path := filepath.Join(t.TempDir(), "credentials.json")
	p.Secrets.DatabaseCredentialsFile = path
	ds.DBDSN = "postgres://app:fixture@127.0.0.1:25432/fixture"
	raw, _ := json.Marshal(map[string]any{"database": map[string]string{"dsn": ds.DBDSN}})
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	ds.PostgresConfig = &install.PostgresConfig{DBName: "fixture", DBUser: "app", DBPassword: "fixture"}
	inv["all"].(map[string]any)["children"].(map[string]any)["databases"] = map[string]any{"hosts": map[string]any{"database": map[string]any{}}}
	directory := t.TempDir()
	prior := []exits.BootstrapEntry{{Name: "primary", Address: "192.0.2.20", Port: 24443, TunnelUUID: "9c92f7c9-a088-4982-a977-9e4fd270b3b5", PinnedPeerCertSHA256: strings.Repeat("a", 64)}}
	ds.Bootstrap = append([]exits.BootstrapEntry(nil), prior...)
	ds.Bootstrap[0].PinnedPeerCertSHA256 = "" // Fresh renderer has not observed the exit certificate.
	if err := preparePreservedPrimaryDesired(p, ds, inv, directory, prior); err != nil {
		t.Fatal(err)
	}
	if ds.PostgresConfig != nil {
		t.Fatal("primary provisioning survived preservation mode")
	}
	if err := prepareBootstrapVariables(p, ds, inv, inspection, directory); err != nil {
		t.Fatal(err)
	}
	db := dependencyVars(inv, "databases", "database")
	for _, key := range []string{"ultra_postgres", "ultra_database_import_dump", "ultra_database_import_password"} {
		if _, found := db[key]; found {
			t.Fatalf("primary mutation input leaked: %s", key)
		}
	}
	bridge := dependencyVars(inv, "bridge", "bridge")
	if _, found := bridge["ultra_postgres_replica"]; found {
		t.Fatal("standby recreation input leaked")
	}
	common := inv["all"].(map[string]any)["vars"].(map[string]any)
	if common["ultra_preserved_primary_routes"].([]exits.BootstrapEntry)[0].PinnedPeerCertSHA256 != prior[0].PinnedPeerCertSHA256 {
		t.Fatal("fresh renderer replaced original TLS trust")
	}
	if common["ultra_generate_exit_tls"] != false || common["ultra_preserve_primary"] != true {
		t.Fatal("preserved primary or TLS mode missing")
	}
	if err := validatePreservedPrimaryFrozenMode(p, inv); err != nil {
		t.Fatal(err)
	}
	delete(p.SourceValues, preservePrimarySourceKey)
	if err := validatePreservedPrimaryFrozenMode(p, inv); err == nil {
		t.Fatal("ordinary bootstrap reused a preserved-primary frozen request")
	}
	ds.DBDSN = "postgres://app:changed@127.0.0.1:25432/fixture"
	if err := preparePreservedPrimaryDesired(p, ds, inv, directory, prior); err == nil {
		t.Fatal("changed primary credentials accepted")
	}
}

func TestPreservedPrimaryRoutesRetainExactTunnelIdentity(t *testing.T) {
	p := &installplan.InstallPlan{Exits: []installplan.ExitNode{{Name: "main", DialAddr: "192.0.2.20", Port: 24443}}}
	route := exits.BootstrapEntry{Name: "main", Address: "192.0.2.20", Port: 24443, TunnelUUID: "9c92f7c9-a088-4982-a977-9e4fd270b3b5", PinnedPeerCertSHA256: strings.Repeat("a", 64)}
	inspection := func(raw []byte) map[string]bootstrapInspection {
		wire, _ := json.Marshal(map[string]any{"files": []map[string]string{{"source": exits.BootstrapFileName, "content": base64.StdEncoding.EncodeToString(raw)}}})
		var i bootstrapInspection
		if err := json.Unmarshal(wire, &i); err != nil {
			t.Fatal(err)
		}
		return map[string]bootstrapInspection{"bridge": i}
	}
	raw, _ := json.Marshal([]exits.BootstrapEntry{route})
	got, err := preservedPrimaryBootstrapRoutes(p, inspection(raw))
	if err != nil || len(got) != 1 || got[0].TunnelUUID != route.TunnelUUID || got[0].PinnedPeerCertSHA256 != route.PinnedPeerCertSHA256 {
		t.Fatalf("route identity not retained: %v", err)
	}
	dynamic := exits.BootstrapEntry{Name: "vultr-atl", Address: "192.0.2.99", Port: 51001, TunnelUUID: "44444444-4444-4444-8444-444444444444", Priority: 75, Enabled: exits.BootstrapEnabledPtr(true)}
	full, _ := json.Marshal([]exits.BootstrapEntry{route, dynamic})
	got, err = preservedPrimaryBootstrapRoutes(p, inspection(full))
	if err != nil || len(got) != 1 || got[0].Name != route.Name || got[0].PinnedPeerCertSHA256 != route.PinnedPeerCertSHA256 {
		t.Fatalf("unmanaged database routes were not preserved outside the managed bootstrap subset: %v", err)
	}
	ambiguous, _ := json.Marshal([]exits.BootstrapEntry{route, route})
	if _, err := preservedPrimaryBootstrapRoutes(p, inspection(ambiguous)); err == nil {
		t.Fatal("ambiguous managed route accepted")
	}
	for _, invalid := range [][]byte{nil, []byte(`[]`), []byte(`[{"name":"main","name":"other"}]`)} {
		if _, err := preservedPrimaryBootstrapRoutes(p, inspection(invalid)); err == nil {
			t.Fatal("missing, changed or ambiguous route accepted")
		}
	}
	p.Exits[0].DialAddr = "192.0.2.21"
	if _, err := preservedPrimaryBootstrapRoutes(p, inspection(raw)); err == nil {
		t.Fatal("replacement address silently reused old tunnel identity")
	}
}

func TestPreservedPrimaryPlaybooksExcludePrimaryMutation(t *testing.T) {
	// Parse the actual embedded playbooks, so adding a new unguarded primary
	// task or provisioning role fails this regression test.
	program := `import json,sys,yaml
for name,text in json.load(sys.stdin).items():
 plays=yaml.safe_load(text)
 assert plays[0]['hosts']=='databases'
 assert plays[0]['tasks'][0]['ansible.builtin.import_tasks']=='tasks/preserved-primary-before.yml'
 for play in plays:
  for role in play.get('roles',[]):
   if isinstance(role,dict) and role.get('role') in ('postgres','database_import','postgres_replica'):
    assert 'not (ultra_preserve_primary' in role.get('when',''), (name,role)
  if play['name']=='Prepare primary replication slot and identity':
   for task in play['tasks']:
    assert 'not (ultra_preserve_primary' in task.get('when',''), (name,task)
`
	payload := map[string]string{}
	for _, name := range []string{"bootstrap.yml", "bootstrap-postgres.yml"} {
		raw, err := ansibleassets.Bundle.ReadFile("playbooks/" + name)
		if err != nil {
			t.Fatal(err)
		}
		payload[name] = string(raw)
	}
	raw, _ := json.Marshal(payload)
	cmd := exec.Command("python3", "-c", program)
	cmd.Stdin = strings.NewReader(string(raw))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("primary mutation gate: %v %s", err, output)
	}
}

func TestPreservedPrimaryIdentityAcrossComponentProcesses(t *testing.T) {
	ansible, err := exec.LookPath("ansible-playbook")
	if err != nil {
		t.Skip("local ansible-playbook is unavailable")
	}
	socketDirectory, err := os.MkdirTemp("", "upp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDirectory) })
	listener, err := net.Listen("unix", filepath.Join(socketDirectory, "socket"))
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skip("local Unix sockets are forbidden; Ansible RPC cannot execute")
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = listener.Close()
	directory := t.TempDir()
	bin := filepath.Join(directory, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	observed := filepath.Join(directory, "observed.json")
	write := func(path string, raw []byte, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, raw, mode); err != nil {
			t.Fatal(err)
		}
	}
	write(observed, []byte(`{"system_identifier":"12345","database":"fixture","database_oid":16384,"primary":true}`), 0600)
	// Replace only the PostgreSQL executable with a fixture. The actual Ansible
	// tasks, assertions and local identity publication run unmodified.
	write(filepath.Join(bin, "runuser"), []byte("#!/bin/sh\ncat "+shellQuote(observed)+"\n"), 0700)
	vars := map[string]any{
		"ultra_preserve_primary": true, "ultra_preserved_primary_database": "fixture",
		"ultra_preserved_primary_host": "192.0.2.40", "ultra_preserved_primary_backup_sha256": strings.Repeat("a", 64),
		"ultra_preserved_primary_backup_snapshot_unix": strconv.FormatInt(time.Now().Unix(), 10),
		"ultra_preserved_primary_identity_file":        filepath.Join(directory, "primary.json"),
		"ansible_connection":                           "local", "ansible_python_interpreter": "/usr/bin/python3",
	}
	inventory := map[string]any{"all": map[string]any{"vars": vars, "children": map[string]any{
		"bridge":    map[string]any{"hosts": map[string]any{"bridge": map[string]any{"ansible_host": "192.0.2.10"}}},
		"exits":     map[string]any{"hosts": map[string]any{"exit_0": map[string]any{"ansible_host": "192.0.2.20"}}},
		"databases": map[string]any{"hosts": map[string]any{"database": map[string]any{"ansible_host": "192.0.2.40"}}},
	}}}
	write(filepath.Join(directory, "inventory.json"), mustPreservedJSON(t, inventory), 0600)
	run := func(stage string, succeeds bool) {
		t.Helper()
		raw, err := ansibleassets.Bundle.ReadFile("playbooks/tasks/preserved-primary-" + stage + ".yml")
		if err != nil {
			t.Fatal(err)
		}
		// Fixture values contain no production data; show failed expressions.
		raw = []byte(strings.ReplaceAll(string(raw), "no_log: true", "no_log: false"))
		task := filepath.Join(directory, stage+".yml")
		write(task, raw, 0600)
		play := filepath.Join(directory, "play.yml")
		write(play, []byte("- hosts: databases\n  gather_facts: false\n  tasks:\n    - ansible.builtin.import_tasks: "+task+"\n"), 0600)
		cmd := exec.Command(ansible, "-i", filepath.Join(directory, "inventory.json"), play)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "ANSIBLE_LOCAL_TEMP="+filepath.Join(directory, "local"), "ANSIBLE_REMOTE_TEMP="+filepath.Join(directory, "remote"))
		output, err := cmd.CombinedOutput()
		if (err == nil) != succeeds {
			t.Fatalf("%s success=%v: %v\n%s", stage, succeeds, err, output)
		}
	}
	run("before", true)
	run("after", true)
	write(observed, []byte(`{"system_identifier":"54321","database":"fixture","database_oid":16384,"primary":true}`), 0600)
	run("after", false)
}

func mustPreservedJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
