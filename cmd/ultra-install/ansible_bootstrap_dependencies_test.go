package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/install"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func dependencyFixture(t *testing.T) (*installplan.InstallPlan, *installplan.DesiredState, map[string]any, map[string]bootstrapInspection) {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "relay")
	if err := os.WriteFile(binary, []byte("pinned-artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	p := &installplan.InstallPlan{Exits: []installplan.ExitNode{{Name: "primary"}}}
	p.Artifacts.RelayBinary = binary
	p.Features.WARP = true
	p.Features.WARPPort = 40000
	ds := &installplan.DesiredState{
		BridgeSpecObject: &config.Spec{SplitRouting: config.BoolPtr(false)},
		ExitSpecObjects:  map[string]*config.Spec{"primary": {AntiCensor: &config.AntiCensorSpec{WARPProxy: true, WARPProxyPort: 40123}}},
	}
	inventory := map[string]any{
		"all": map[string]any{
			"vars": map[string]any{},
			"children": map[string]any{
				"bridge": map[string]any{"hosts": map[string]any{"bridge": map[string]any{}}},
				"exits":  map[string]any{"hosts": map[string]any{"exit_0": map[string]any{}}},
			},
		},
	}
	return p, ds, inventory, map[string]bootstrapInspection{"bridge": {Architecture: "amd64"}, "exit_0": {Architecture: "amd64"}}
}

func dependencyVars(inventory map[string]any, group, alias string) map[string]any {
	return inventory["all"].(map[string]any)["children"].(map[string]any)[group].(map[string]any)["hosts"].(map[string]any)[alias].(map[string]any)
}

func TestBootstrapWARPUsesPreservedExitDependency(t *testing.T) {
	for _, tc := range []struct {
		name                string
		adopt, enabled      bool
		installed, expected int
	}{
		{"adopt custom port", true, true, 40123, 40123},
		{"adopt effective default", true, true, 0, 40000},
		{"adopt disabled ignores plan", true, false, 40123, 40123},
		{"normal uses plan", false, true, 40123, 40000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, ds, inv, inspection := dependencyFixture(t)
			p.AdoptRuntime = tc.adopt
			ds.ExitSpecObjects["primary"].AntiCensor.WARPProxy = tc.enabled
			ds.ExitSpecObjects["primary"].AntiCensor.WARPProxyPort = tc.installed
			if err := prepareBootstrapVariables(p, ds, inv, inspection, t.TempDir()); err != nil {
				t.Fatal(err)
			}
			vars := dependencyVars(inv, "exits", "exit_0")
			if vars["ultra_warp_port"] != tc.expected {
				t.Fatalf("port = %v, want %d", vars["ultra_warp_port"], tc.expected)
			}
			if vars["ultra_warp_enabled"] != (tc.enabled || !tc.adopt) {
				t.Fatal("WARP enablement changed")
			}
			if ds.ExitSpecObjects["primary"].AntiCensor.WARPProxyPort != tc.installed {
				t.Fatal("installed spec mutated")
			}
		})
	}
}

func geoInspection() []bootstrapGeoAsset {
	result := make([]bootstrapGeoAsset, 2)
	for i, name := range []string{"geoip.dat", "geosite.dat"} {
		result[i].Name = name
		result[i].Stat.Path = "/srv/geo/" + name
		result[i].Stat.Exists = true
		result[i].Stat.Regular = true
		result[i].Stat.Size = 100 + int64(i)
		result[i].Stat.Checksum = strings.Repeat("a", 64)
	}
	return result
}

func TestBootstrapAdoptionFreezesInstalledGeoGeneration(t *testing.T) {
	p, ds, inv, inspection := dependencyFixture(t)
	p.AdoptRuntime = true
	p.Features.SkipGeoDownload = true // Operator defaults must not bypass installed dependencies.
	p.Features.GeoReleaseTag = "new-release"
	ds.BridgeSpecObject.SplitRouting = config.BoolPtr(true)
	ds.BridgeSpecObject.GeoAssetsDir = "/srv/geo"
	bridge := inspection["bridge"]
	bridge.GeoAssets = geoInspection()
	inspection["bridge"] = bridge
	if err := prepareBootstrapVariables(p, ds, inv, inspection, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	vars := dependencyVars(inv, "bridge", "bridge")
	if vars["ultra_geo_enabled"] != true {
		t.Fatal("installed split routing dependencies skipped")
	}
	assets := vars["ultra_geo_assets"].([]map[string]any)
	if len(assets) != 2 || assets[0]["path"] != "/srv/geo/geoip.dat" || assets[0]["sha256"] != strings.Repeat("a", 64) {
		t.Fatal("installed geo identity not frozen")
	}
}

func TestBootstrapGeoInspectionFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func([]bootstrapGeoAsset) []bootstrapGeoAsset
	}{
		{"missing", func(a []bootstrapGeoAsset) []bootstrapGeoAsset { return a[:1] }},
		{"absent", func(a []bootstrapGeoAsset) []bootstrapGeoAsset { a[0].Stat.Exists = false; return a }},
		{"symlink", func(a []bootstrapGeoAsset) []bootstrapGeoAsset { a[0].Stat.Symlink = true; return a }},
		{"unknown", func(a []bootstrapGeoAsset) []bootstrapGeoAsset { a[0].Name = "other.dat"; return a }},
		{"duplicate", func(a []bootstrapGeoAsset) []bootstrapGeoAsset { a[1] = a[0]; return a }},
		{"wrong path", func(a []bootstrapGeoAsset) []bootstrapGeoAsset { a[0].Stat.Path = "/other/geoip.dat"; return a }},
		{"unknown sha", func(a []bootstrapGeoAsset) []bootstrapGeoAsset { a[0].Stat.Checksum = ""; return a }},
		{"empty", func(a []bootstrapGeoAsset) []bootstrapGeoAsset { a[0].Stat.Size = 0; return a }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := preservedBootstrapGeoAssets("/srv/geo", tc.alter(geoInspection())); err == nil {
				t.Fatal("unverified asset accepted")
			}
		})
	}
}

func TestBootstrapNormalGeoSelectionUnchanged(t *testing.T) {
	p, ds, inv, inspection := dependencyFixture(t)
	ds.BridgeSpecObject.SplitRouting = config.BoolPtr(true)
	p.Features.GeoReleaseTag = "pinned-release"
	if err := prepareBootstrapVariables(p, ds, inv, inspection, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	vars := dependencyVars(inv, "bridge", "bridge")
	if vars["ultra_geo_enabled"] != true || vars["ultra_geo_tag"] != "pinned-release" {
		t.Fatal("normal geo selection changed")
	}
	if _, ok := vars["ultra_geo_assets"]; ok {
		t.Fatal("normal install requires installed geo")
	}
}

// Exercises the real stat/assert path: a bogus release tag must never cause a
// download, and changes after inspection must fail before relay activation.
func TestBootstrapPreservedGeoRole(t *testing.T) {
	executable := os.Getenv("ULTRA_TEST_ANSIBLE_PLAYBOOK")
	if executable == "" {
		t.Skip("set ULTRA_TEST_ANSIBLE_PLAYBOOK for local Ansible role verification")
	}
	directory := t.TempDir()
	assets := []map[string]any{}
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		content := []byte("installed generation " + name)
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(content)
		assets = append(assets, map[string]any{"name": name, "path": path, "size": len(content), "sha256": fmt.Sprintf("%x", sum)})
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	role := filepath.Join(cwd, "../../deploy/ansible/roles/geo")
	playbook := filepath.Join(directory, "play.yml")
	text := fmt.Sprintf("- hosts: localhost\n  gather_facts: false\n  connection: local\n  roles:\n    - %s\n", role)
	if err = os.WriteFile(playbook, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	vars, err := json.Marshal(
		map[string]any{
			"ultra_preserve_runtime":     true,
			"ultra_geo_tag":              "does-not-exist",
			"ultra_spec":                 map[string]any{"geo_assets_dir": directory},
			"ultra_geo_assets":           assets,
			"ansible_python_interpreter": filepath.Join(filepath.Dir(executable), "python"),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	varsPath := filepath.Join(directory, "vars.json")
	if err = os.WriteFile(varsPath, vars, 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "ansible.cfg")
	if err = os.WriteFile(configPath, []byte("[defaults]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	run := func() ([]byte, error) {
		command := exec.Command(executable, "-i", "localhost,", playbook, "-e", "@"+varsPath)
		command.Env = append(
			os.Environ(),
			"ANSIBLE_CONFIG="+configPath,
			"ANSIBLE_LOCAL_TEMP="+filepath.Join(directory, "local"),
			"ANSIBLE_REMOTE_TEMP="+filepath.Join(directory, "remote"),
			"ANSIBLE_NOCOLOR=1",
		)
		return command.CombinedOutput()
	}
	if output, err := run(); err != nil {
		t.Fatalf("preserved role failed: %v\n%s", err, output)
	}
	for _, asset := range assets {
		content, err := os.ReadFile(asset["path"].(string))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(content)
		if fmt.Sprintf("%x", sum) != asset["sha256"] {
			t.Fatal("adoption replaced installed geo generation")
		}
	}
	if err = os.WriteFile(assets[0]["path"].(string), []byte("different generation"), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := run(); err == nil {
		t.Fatalf("changed geo asset accepted\n%s", output)
	}
	if err = os.Remove(assets[0]["path"].(string)); err != nil {
		t.Fatal(err)
	}
	if output, err := run(); err == nil {
		t.Fatalf("missing geo asset accepted\n%s", output)
	}
}

func TestBootstrapPreservedWARPRole(t *testing.T) {
	executable := os.Getenv("ULTRA_TEST_ANSIBLE_PLAYBOOK")
	if executable == "" {
		t.Skip("set ULTRA_TEST_ANSIBLE_PLAYBOOK for local Ansible role verification")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	directory := t.TempDir()
	logPath := filepath.Join(directory, "commands")
	cliPath := filepath.Join(directory, "warp-cli")
	writeCLI := func(settings, status string) {
		shellQuote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
		script := fmt.Sprintf(
			"#!/bin/sh\nprintf '%%s\\n' \"$*\" >> %s\ncase \"$2\" in\nsettings) printf '%%s\\n' %s;;\nstatus) printf '%%s\\n' %s;;\n*) exit 91;;\nesac\n",
			strconv.Quote(logPath),
			shellQuote(settings),
			shellQuote(status),
		)
		if err := os.WriteFile(cliPath, []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	playbook := filepath.Join(directory, "play.yml")
	text := fmt.Sprintf(
		"- hosts: localhost\n  gather_facts: false\n  connection: local\n  roles:\n    - %s\n",
		filepath.Join(cwd, "../../deploy/ansible/roles/warp"),
	)
	if err = os.WriteFile(playbook, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	vars, err := json.Marshal(
		map[string]any{
			"ultra_preserve_runtime":     true,
			"ultra_warp_port":            port,
			"ansible_python_interpreter": filepath.Join(filepath.Dir(executable), "python"),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	varsPath := filepath.Join(directory, "vars.json")
	if err = os.WriteFile(varsPath, vars, 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "ansible.cfg")
	if err = os.WriteFile(configPath, []byte("[defaults]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	run := func() ([]byte, error) {
		command := exec.Command(executable, "-i", "localhost,", playbook, "-e", "@"+varsPath)
		command.Env = append(
			os.Environ(),
			"PATH="+directory+":"+os.Getenv("PATH"),
			"ANSIBLE_CONFIG="+configPath,
			"ANSIBLE_LOCAL_TEMP="+filepath.Join(directory, "local"),
			"ANSIBLE_REMOTE_TEMP="+filepath.Join(directory, "remote"),
			"ANSIBLE_NOCOLOR=1",
		)
		return command.CombinedOutput()
	}
	for _, tc := range []struct {
		name, settings, status string
		valid                  bool
	}{
		{"legacy WarpProxy", fmt.Sprintf("Mode: WarpProxy\nProxy Port: %d", port), "Status: Connected", true},
		{"legacy Proxy", fmt.Sprintf("Mode: Proxy\nProxy Port: %d", port), "Status update: Connected", true},
		{"combined user setting", fmt.Sprintf("(user set)\tMode: WarpProxy on port %d", port), "Status update: Connected", true},
		{"legacy wrong port", fmt.Sprintf("Mode: WarpProxy\nProxy Port: %d", port+1), "Status: Connected", false},
		{"combined wrong port", fmt.Sprintf("(user set)\tMode: WarpProxy on port %d", port+1), "Status: Connected", false},
		{"combined conflicting port", fmt.Sprintf("Mode: WarpProxy on port %d\nProxy Port: %d", port+1, port), "Status: Connected", false},
		{"legacy wrong mode", fmt.Sprintf("Mode: Warp\nProxy Port: %d", port), "Status: Connected", false},
		{"combined wrong mode", fmt.Sprintf("(user set)\tMode: Warp on port %d", port), "Status: Connected", false},
		{"combined mode suffix", fmt.Sprintf("Mode: WarpProxy on port %d extra", port), "Status: Connected", false},
		{"combined wrong prefix", fmt.Sprintf("Other Mode: WarpProxy on port %d", port), "Status: Connected", false},
		{"combined disconnected", fmt.Sprintf("(user set)\tMode: WarpProxy on port %d", port), "Status: Disconnected", false},
		{"legacy disconnected", fmt.Sprintf("Mode: WarpProxy\nProxy Port: %d", port), "Status: Connected but unavailable", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeCLI(tc.settings, tc.status)
			if err := os.Remove(logPath); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			output, runErr := run()
			if runErr == nil && !tc.valid || runErr != nil && tc.valid {
				t.Fatalf("valid=%v, error=%v\n%s", tc.valid, runErr, output)
			}
			commands, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(commands) != "--accept-tos settings\n--accept-tos status\n" {
				t.Fatalf("WARP mutating commands called: %s", commands)
			}
		})
	}
}

// Run the actual settings tasks in isolation, without package or service writes.
func TestBootstrapManagedWARPSettings(t *testing.T) {
	executable := os.Getenv("ULTRA_TEST_ANSIBLE_PLAYBOOK")
	if executable == "" {
		t.Skip("set ULTRA_TEST_ANSIBLE_PLAYBOOK for local Ansible role verification")
	}
	directory := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	playbook := filepath.Join(directory, "play.json")
	python := filepath.Join(filepath.Dir(executable), "python")
	extract := exec.Command(python, "-c", `import json,sys,yaml
with open(sys.argv[1]) as f:
    block = yaml.safe_load(f)[0]['block']
names = ['Inspect WARP settings', 'Select WARP proxy mode', 'Configure WARP proxy port']
tasks = [task for task in block if task['name'] in names]
assert [task['name'] for task in tasks] == names
with open(sys.argv[2], 'w') as f:
    json.dump([{'hosts': 'localhost', 'gather_facts': False, 'connection': 'local', 'tasks': tasks}], f)
`, filepath.Join(cwd, "../../deploy/ansible/roles/warp/tasks/main.yml"), playbook)
	if output, err := extract.CombinedOutput(); err != nil {
		t.Fatalf("extract actual role tasks: %v\n%s", err, output)
	}
	configPath := filepath.Join(directory, "ansible.cfg")
	if err := os.WriteFile(configPath, []byte("[defaults]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, settings, setters string
	}{
		{"combined correct", "(user set)\tMode: WarpProxy on port 40123", ""},
		{"legacy correct", "Mode: WarpProxy\nProxy Port: 40123", ""},
		{"combined wrong port", "(user set)\tMode: WarpProxy on port 40124", "--accept-tos proxy port 40123\n"},
		{"combined wrong mode", "(user set)\tMode: Warp on port 40123", "--accept-tos mode proxy\n--accept-tos proxy port 40123\n"},
		{"wrong mode with legacy port", "Mode: Warp\nProxy Port: 40123", "--accept-tos mode proxy\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logPath := filepath.Join(directory, "commands")
			if err := os.Remove(logPath); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			script := fmt.Sprintf(
				"#!/bin/sh\nprintf '%%s\\n' \"$*\" >> %s\nif [ \"$2\" = settings ]; then printf '%%s\\n' '%s'; fi\n",
				strconv.Quote(logPath),
				tc.settings,
			)
			if err := os.WriteFile(filepath.Join(directory, "warp-cli"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			vars, err := json.Marshal(map[string]any{"ultra_warp_port": 40123, "ansible_python_interpreter": python})
			if err != nil {
				t.Fatal(err)
			}
			command := exec.Command(executable, "-i", "localhost,", playbook, "-e", string(vars))
			command.Env = append(
				os.Environ(),
				"PATH="+directory+":"+os.Getenv("PATH"),
				"ANSIBLE_CONFIG="+configPath,
				"ANSIBLE_LOCAL_TEMP="+filepath.Join(directory, "local"),
				"ANSIBLE_REMOTE_TEMP="+filepath.Join(directory, "remote"),
				"ANSIBLE_NOCOLOR=1",
			)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("managed WARP settings failed: %v\n%s", err, output)
			}
			commands, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(commands) != "--accept-tos settings\n"+tc.setters {
				t.Fatalf("unexpected commands: %s", commands)
			}
		})
	}
}

func TestFleetIdentityUsesRootControlledParentAndPrivateRuntimeKey(t *testing.T) {
	root := filepath.Join("..", "..")
	read := func(path string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	generate := read("deploy/ansible/roles/fleet_access/tasks/generate.yml")
	for _, part := range []string{"loop: [/etc, /etc/ultra-fleet]", "follow: false", "item.stat.uid == 0", "mode: \"0750\"", "owner: ultra-relay", "mode: \"0600\""} {
		if !strings.Contains(generate, part) {
			t.Fatalf("missing fleet contract %s", part)
		}
	}
	if strings.Index(generate, "Reject writable or linked") > strings.Index(generate, "Create private runtime") {
		t.Fatal("ancestry check occurs after mutation")
	}
	env := read("deploy/ansible/roles/recovery_primary/templates/automation.conf.j2")
	if !strings.Contains(env, "ULTRA_VULTR_SSH_KEY_FILE=/etc/ultra-fleet/id_ed25519") {
		t.Fatal("runtime identity not configured")
	}
	planner := read("deploy/recovery/bootstrap_plan.py")
	if !strings.Contains(planner, "state_paths = ['/etc/ultra-fleet'") {
		t.Fatal("fleet identity not preserved")
	}
	automation := read("deploy/ansible/playbooks/bootstrap-automation.yml")
	stage := strings.Index(automation, "fleet_access_ultra_stage: authorize")
	recovery := strings.Index(automation, "- recovery_primary")
	if stage < 0 || recovery < 0 || stage > recovery {
		t.Fatal("planner runs before authorization")
	}
}

func TestBootstrapDumpPreflightPrecedesDatabaseMutation(t *testing.T) {
	for _, name := range []string{"bootstrap.yml", "bootstrap-postgres.yml"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "ansible", "playbooks", name))
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		if !strings.Contains(s, "tasks_from: preflight") ||
			strings.Index(s, "tasks_from: preflight") > strings.Index(s, "- role: postgres\n") {
			t.Fatal("archive must be checked before provisioning")
		}
		if !strings.Contains(s, "ansible_host == ultra_db_tunnel_host") {
			t.Fatal("dedicated target assertion missing")
		}
	}
}

func TestBootstrapDumpHelperIsEmbeddedAndFrozenOutsideCheckout(t *testing.T) {
	p, ds, inv, inspection := dependencyFixture(t)
	p.Secrets.DatabaseDumpFile = filepath.Join(t.TempDir(), "database.dump")
	p.Secrets.DatabaseDumpSHA256 = strings.Repeat("a", 64)
	ds.PostgresConfig = &install.PostgresConfig{DBName: "app", DBUser: "app", DBPassword: "fixture"}
	inv["all"].(map[string]any)["children"].(map[string]any)["databases"] = map[string]any{
		"hosts": map[string]any{"database": map[string]any{}},
	}
	directory := t.TempDir()
	t.Chdir(t.TempDir())
	if err := prepareBootstrapVariables(p, ds, inv, inspection, directory); err != nil {
		t.Fatal(err)
	}
	vars := dependencyVars(inv, "databases", "database")
	helper := filepath.Join(vars["ultra_database_import_script_directory"].(string), "database_dump_import.py")
	data, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "def preflight(") {
		t.Fatal("embedded helper missing")
	}
	info, _ := os.Stat(helper)
	if info.Mode().Perm() != 0600 {
		t.Fatal("helper not private")
	}
	if vars["ultra_database_import_sha256"] != p.Secrets.DatabaseDumpSHA256 {
		t.Fatal("dump digest not frozen")
	}
}

func TestPostgresIdentityObservationGrantTargetsApplicationDatabase(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "ansible", "roles", "postgres", "tasks", "main.yml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	start := strings.Index(s, "- name: Authorize cluster identity observation")
	end := strings.Index(s, "- name: Apply PostgreSQL settings")
	if start < 0 || end < start {
		t.Fatal("application grant missing")
	}
	grant := s[start:end]
	if !strings.Contains(grant, "--dbname, \"{{ ultra_postgres.name }}\"") ||
		!strings.Contains(grant, "GRANT EXECUTE ON FUNCTION pg_control_system()") {
		t.Fatal("grant must run in the app DB")
	}
	if strings.Contains(s[:start], "GRANT EXECUTE") {
		t.Fatal("grant must not run in default maintenance database")
	}
	if strings.Index(s, "CREATE DATABASE") > start {
		t.Fatal("grant precedes app database creation")
	}
	if strings.Index(s, "Verify application login") < end {
		t.Fatal("login check must follow grant")
	}
}
