package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	recoveryassets "github.com/NikitaDmitryuk/ultra/deploy/recovery"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

type bootstrapGeoAsset struct {
	Name string `json:"item"`
	Stat struct {
		Path     string `json:"path"`
		Exists   bool   `json:"exists"`
		Regular  bool   `json:"isreg"`
		Symlink  bool   `json:"islnk"`
		Checksum string `json:"checksum"`
		Size     int64  `json:"size"`
	} `json:"stat"`
}

type bootstrapInspection struct {
	AuthoritativeRoutes []exits.BootstrapEntry `json:"-"`
	TopologySHA         string                 `json:"-"`
	CertificatePin      string                 `json:"certificate_pin"`
	GeoAssets           []bootstrapGeoAsset    `json:"geo_assets"`
	Architecture        string                 `json:"architecture"`
	Capabilities        []string               `json:"capabilities"`
	Files               []struct {
		Content string `json:"content"`
		Source  string `json:"source"`
	} `json:"files"`
}

func (i bootstrapInspection) file(name string) ([]byte, error) {
	for _, f := range i.Files {
		if filepath.Base(f.Source) == name {
			return base64.StdEncoding.DecodeString(f.Content)
		}
	}
	return nil, nil
}

// bootstrapInventory is a derived inventory; it never reads a second operator inventory.
func bootstrapInventory(p *installplan.InstallPlan, directory string) (map[string]any, error) {
	return bootstrapInventoryWithNativeAttestation(p, directory, attestNativeAdoption)
}

func bootstrapInventoryWithNativeAttestation(p *installplan.InstallPlan, directory string, attest func(*installplan.InstallPlan) (string, error)) (map[string]any, error) {

	if p.Bridge.RemoteDir != "/etc/ultra-relay" {
		return nil, fmt.Errorf("ansible bootstrap requires canonical remote directory /etc/ultra-relay")
	}
	if p.BridgeSSHIdentity() == "" {
		return nil, fmt.Errorf("explicit pinned SSH identity required")
	}
	pins := os.Getenv("ULTRA_INSTALL_SSH_KNOWN_HOSTS")
	if p.Automation != nil {
		pins = p.Automation.KnownHostsFile
	}
	if pins == "" {
		pins = filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts")
	}
	pins, err := filepath.Abs(pins)
	if err != nil {
		return nil, err
	}
	if _, err = os.Stat(pins); err != nil {
		return nil, fmt.Errorf("SSH pins required: %w", err)
	}
	identity, err := filepath.Abs(p.BridgeSSHIdentity())
	if err != nil {
		return nil, err
	}
	common := map[string]any{"ansible_user": p.SSH.User, "ansible_become": p.SSH.User != "root", "ansible_become_method": "sudo", "ansible_become_flags": "-H -S -n", "ansible_ssh_private_key_file": identity, "ansible_ssh_common_args": "-F /dev/null -o ControlMaster=no -o ControlPath=none -o UpdateHostKeys=no -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=" + shellQuote(pins), "ultra_remote_dir": p.Bridge.RemoteDir, "ultra_inspect_dir": filepath.Join(directory, "inspection")}
	bridge := map[string]any{"ansible_host": p.Bridge.SSHHost}
	if p.BridgeNative {
		if _, err := attest(p); err != nil {
			return nil, err
		}
	}
	if p.BridgeNative || localLifecycleBridge(p) {
		bridge["ansible_connection"] = "local"
	}
	nodes := map[string]any{}
	for n, ex := range p.Exits {
		exitIdentity := p.ExitSSHIdentity(ex)
		if exitIdentity == "" {
			return nil, fmt.Errorf("explicit pinned exit SSH identity required")
		}
		exitIdentity, err = filepath.Abs(exitIdentity)
		if err != nil {
			return nil, err
		}
		nodes["exit_"+strconv.Itoa(n)] = map[string]any{"ansible_host": ex.SSHHost, "ansible_ssh_private_key_file": exitIdentity}
	}
	db := map[string]any{}
	if p.Database.Enabled {
		if p.Database.PrimaryHost == "" || p.Database.PrimaryHost == p.Bridge.SSHHost || p.Database.PrimaryHost == p.Bridge.Address {
			return nil, fmt.Errorf("dedicated database server required")
		}
		dbIdentity := p.Database.SSHIdentity
		if dbIdentity == "" {
			dbIdentity = p.SSH.Identity
		}
		if dbIdentity == "" {
			return nil, fmt.Errorf("explicit pinned database SSH identity required")
		}
		dbIdentity, err = filepath.Abs(dbIdentity)
		if err != nil {
			return nil, err
		}
		dbUser := p.Database.SSHUser
		if dbUser == "" {
			dbUser = p.SSH.User
		}
		db["database"] = map[string]any{"ansible_host": p.Database.PrimaryHost, "ansible_user": dbUser, "ansible_become": dbUser != "root", "ansible_ssh_private_key_file": dbIdentity}
		common["ultra_db_tunnel_host"] = p.Database.PrimaryHost
		common["ultra_db_tunnel_known_hosts_source"] = pins

	}
	return map[string]any{"all": map[string]any{"vars": common, "children": map[string]any{"bridge": map[string]any{"hosts": map[string]any{"bridge": bridge}}, "exits": map[string]any{"hosts": nodes}, "databases": map[string]any{"hosts": db}}}}, nil
}

func inspectBootstrap(ctx context.Context, p *installplan.InstallPlan, directory, python, executable string, lockRoots ...string) (map[string]any, map[string]bootstrapInspection, error) {
	return inspectBootstrapWithTopology(ctx, p, directory, python, executable, true, lockRoots...)
}

func inspectBootstrapWithTopology(ctx context.Context, p *installplan.InstallPlan, directory, python, executable string, discoverTopology bool, lockRoots ...string) (map[string]any, map[string]bootstrapInspection, error) {
	var topology *adoptionTopology
	if p.AdoptRuntime && discoverTopology {
		lockRoot := filepath.Dir(directory)
		if len(lockRoots) > 0 {
			lockRoot = lockRoots[0]
		}
		observed, err := inspectAdoptionTopology(ctx, p, directory, python, executable, lockRoot)
		if err != nil {
			return nil, nil, err
		}
		topology = &observed
	}
	inventory, err := bootstrapInventory(p, directory)
	if err != nil {
		return nil, nil, err
	}
	var authoritativeRoutes []exits.BootstrapEntry
	inventory["all"].(map[string]any)["vars"].(map[string]any)["ultra_preserve_runtime"] = p.AdoptRuntime
	if topology != nil {
		authoritativeRoutes, err = applyAdoptionTopology(p, inventory, directory, *topology)
		if err != nil {
			return nil, nil, err
		}
	}
	if err = os.MkdirAll(filepath.Join(directory, "inspection"), 0700); err != nil {
		return nil, nil, err
	}
	lockRoot := filepath.Dir(directory)
	if len(lockRoots) > 0 {
		lockRoot = lockRoots[0]
	}
	_, err = deployansible.RunLocal(ctx, "inspect-bootstrap", inventory, map[string]any{"ultra_lock_directory": lockRoot}, filepath.Join(directory, "inspect"), python, executable)
	if err != nil {
		return nil, nil, err
	}
	result := map[string]bootstrapInspection{}
	aliases := []string{"bridge"}
	for n := range p.Exits {
		aliases = append(aliases, "exit_"+strconv.Itoa(n))
	}
	for _, alias := range aliases {
		raw, err := os.ReadFile(filepath.Join(directory, "inspection", alias+".json"))
		if err != nil {
			return nil, nil, err
		}
		var data bootstrapInspection
		if err = json.Unmarshal(raw, &data); err != nil {
			return nil, nil, err
		}
		if data.Architecture != "amd64" && data.Architecture != "arm64" {
			return nil, nil, fmt.Errorf("unsupported target architecture")
		}
		result[alias] = data
	}
	bridgeInspection := result["bridge"]
	bridgeInspection.AuthoritativeRoutes = authoritativeRoutes
	if topology != nil {
		bridgeInspection.TopologySHA = topology.SHA256
		if err := validateAdoptionTopologyInspection(*topology, result); err != nil {
			return nil, nil, err
		}
	}
	result["bridge"] = bridgeInspection
	return inventory, result, nil
}

func bootstrapRenderOptions(p *installplan.InstallPlan, inspection map[string]bootstrapInspection) (installplan.RenderOptions, error) {
	opts := installplan.RenderOptions{PreserveRuntime: p.AdoptRuntime}
	raw, err := inspection["bridge"].file("spec.json")
	if err != nil {
		return opts, err
	}
	if len(raw) == 0 {
		if p.Bridge.ReuseSpec {
			return opts, fmt.Errorf("existing bridge specification required")
		}
		return opts, nil
	}
	p.Bridge.ReuseSpec = true
	var prior config.Spec
	if err = json.Unmarshal(raw, &prior); err != nil {
		return opts, fmt.Errorf("existing bridge specification is invalid")
	}
	if prior.Role != config.RoleBridge {
		return opts, fmt.Errorf("existing target is not a bridge")
	}
	opts.ExistingBridge = &prior
	opts.ExistingBridgeJSON = append([]byte(nil), raw...)
	if err = checkPublishedIngressPlan(p, &prior); err != nil {
		return opts, err
	}
	env, err := inspection["bridge"].file("environment")
	if err != nil {
		return opts, err
	}
	for _, line := range strings.Split(string(env), "\n") {
		if strings.HasPrefix(line, "ULTRA_RELAY_ADMIN_TOKEN=") {
			opts.ExistingAdminToken = strings.TrimPrefix(line, "ULTRA_RELAY_ADMIN_TOKEN=")
		}
	}
	if opts.ExistingAdminToken == "" {
		return opts, fmt.Errorf("existing bridge admin identity is unavailable")
	}
	raw, err = inspection["bridge"].file(exits.BootstrapFileName)
	if err != nil {
		return opts, err
	}
	if len(raw) > 0 {
		if err = json.Unmarshal(raw, &opts.PriorBootstrap); err != nil {
			return opts, fmt.Errorf("existing bootstrap routes are invalid")
		}
	}
	if p.AdoptRuntime && len(inspection["bridge"].AuthoritativeRoutes) > 0 {
		opts.PriorBootstrap = append([]exits.BootstrapEntry(nil), inspection["bridge"].AuthoritativeRoutes...)
	}
	if len(opts.PriorBootstrap) == 0 && prior.Exit.Address != "" {
		if p.AdoptRuntime {
			return opts, fmt.Errorf("runtime adoption requires existing bootstrap routes")
		}
		opts.PriorBootstrap = []exits.BootstrapEntry{{Name: "primary", Address: prior.Exit.Address, Port: prior.Exit.Port, TunnelUUID: prior.Exit.TunnelUUID, Priority: 100}}
	}
	for n := range p.Exits {
		ex := &p.Exits[n]
		if p.AdoptRuntime {
			raw, err = inspection["exit_"+strconv.Itoa(n)].file("spec.json")
			if err != nil || len(raw) == 0 {
				return opts, fmt.Errorf("runtime adoption requires each existing exit specification")
			}
			var old config.Spec
			if err = json.Unmarshal(raw, &old); err != nil || old.Role != config.RoleExit {
				return opts, fmt.Errorf("existing exit specification is invalid")
			}
			if opts.ExistingExits == nil {
				opts.ExistingExits = map[string]*config.Spec{}
			}
			opts.ExistingExits[ex.Name] = &old
			if opts.ExistingExitJSON == nil {
				opts.ExistingExitJSON = map[string][]byte{}
			}
			opts.ExistingExitJSON[ex.Name] = append([]byte(nil), raw...)
			continue
		}
		if ex.TunnelUUID != "" {
			continue
		}
		if id := exits.BootstrapTunnelUUID(opts.PriorBootstrap, ex.DialAddr, ex.Port); id != "" {
			ex.TunnelUUID = id
			continue
		}
		raw, err = inspection["exit_"+strconv.Itoa(n)].file("spec.json")
		if err != nil {
			return opts, err
		}
		if len(raw) > 0 {
			var old config.Spec
			if err = json.Unmarshal(raw, &old); err != nil || old.Role != config.RoleExit {
				return opts, fmt.Errorf("existing exit specification is invalid")
			}
			ex.TunnelUUID = old.Exit.TunnelUUID
		}
	}
	return opts, nil
}

func sourceSHA(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, err = io.Copy(hash, file)
	closeErr := file.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func prepareBootstrapVariables(p *installplan.InstallPlan, ds *installplan.DesiredState, inventory map[string]any, inspection map[string]bootstrapInspection, directory string) error {
	if ds.DBDSN != "" && !p.Database.Enabled {
		return fmt.Errorf("explicit dedicated DB_HOST required before installing an existing database-backed bridge")
	}
	all := inventory["all"].(map[string]any)
	children := all["children"].(map[string]any)
	bridge := children["bridge"].(map[string]any)["hosts"].(map[string]any)["bridge"].(map[string]any)
	nodes := children["exits"].(map[string]any)["hosts"].(map[string]any)
	all["vars"].(map[string]any)["ultra_host_bootstrap"] = true
	all["vars"].(map[string]any)["ultra_bridge_ipv4"] = p.Bridge.Address
	all["vars"].(map[string]any)["ultra_preserve_runtime"] = p.AdoptRuntime
	exitAliases := map[string]string{}
	binary := func(arch, kind string) (string, error) {
		value := p.Artifacts.RelayBinary
		if kind == "bot" {
			value = p.Artifacts.BotBinary
		}
		if p.FullAutomation() {
			value = filepath.Join(p.Automation.ReleaseDir, "ultra-"+kind+"-linux-"+arch)
		}
		if value == "" {
			return "", fmt.Errorf("pinned %s binary required", kind)
		}
		return filepath.Abs(value)
	}
	for n, ex := range p.Exits {
		alias := "exit_" + strconv.Itoa(n)
		vars := nodes[alias].(map[string]any)
		src, err := binary(inspection[alias].Architecture, "relay")
		if err != nil {
			return err
		}
		sum, err := sourceSHA(src)
		if err != nil {
			return err
		}
		vars["ultra_relay_source"] = src
		vars["ultra_relay_sha256"] = sum
		vars["ultra_spec"] = ds.ExitSpecObjects[ex.Name]
		vars["ultra_result_file"] = filepath.Join(directory, alias+"-result.json")
		oldEnvironment, err := inspection[alias].file("environment")
		if err != nil {
			return err
		}
		vars["ultra_relay_environment"] = mergeBootstrapEnvironment(string(oldEnvironment), ds.ExitEnvs[ex.Name])
		if p.AdoptRuntime {
			vars["ultra_relay_environment"] = string(oldEnvironment)
		}
		vars["ultra_generate_exit_tls"] = p.Features.GenerateExitTLS
		vars["ultra_warp_enabled"] = p.Features.WARP
		vars["ultra_warp_port"] = p.Features.WARPPort
		if p.AdoptRuntime {
			spec := ds.ExitSpecObjects[ex.Name]
			vars["ultra_warp_enabled"] = spec.AntiCensor != nil && spec.AntiCensor.WARPProxy
			port := 40000 // Same effective default as the exit Xray generator.
			if spec.AntiCensor != nil && spec.AntiCensor.WARPProxyPort > 0 {
				port = spec.AntiCensor.WARPProxyPort
			}
			vars["ultra_warp_port"] = port
		}
		exitAliases[ex.Name] = alias
	}
	src, err := binary(inspection["bridge"].Architecture, "relay")
	if err != nil {
		return err
	}
	sum, err := sourceSHA(src)
	if err != nil {
		return err
	}
	ports := []int{ds.BridgeSpecObject.VLESSPort}
	if p.Bot.Enabled {
		ports = append(ports, 80, 443, p.Bot.Port)
	}
	if ds.BridgeSpecObject.AntiCensor != nil && ds.BridgeSpecObject.AntiCensor.PublicXHTTPPort > 0 {
		ports = append(ports, ds.BridgeSpecObject.AntiCensor.PublicXHTTPPort)
	}
	bridge["ultra_bridge_ports"] = ports
	bridge["ultra_relay_source"] = src
	bridge["ultra_relay_sha256"] = sum
	bridge["ultra_spec"] = ds.BridgeSpecObject
	oldEnvironment, err := inspection["bridge"].file("environment")
	if err != nil {
		return err
	}
	bridge["ultra_relay_environment"] = mergeBootstrapEnvironment(string(oldEnvironment), ds.BridgeEnv)
	if p.AdoptRuntime {
		bridge["ultra_relay_environment"] = string(oldEnvironment)
	}
	bridge["ultra_bootstrap_entries"] = ds.Bootstrap
	bridge["ultra_exit_hosts"] = exitAliases
	bridge["ultra_bot_enabled"] = p.Bot.Enabled
	bridge["ultra_geo_enabled"] = !p.Features.SkipGeoDownload && ds.BridgeSpecObject.SplitRoutingEnabled()
	bridge["ultra_geo_tag"] = p.Features.GeoReleaseTag
	if p.AdoptRuntime {
		bridge["ultra_geo_enabled"] = ds.BridgeSpecObject.SplitRoutingEnabled()
		if ds.BridgeSpecObject.SplitRoutingEnabled() {
			assets, err := preservedBootstrapGeoAssets(ds.BridgeSpecObject.GeoAssetsDir, inspection["bridge"].GeoAssets)
			if err != nil {
				return err
			}
			bridge["ultra_geo_assets"] = assets
		}
	}
	if ds.PostgresConfig != nil {
		c := ds.PostgresConfig
		children["databases"].(map[string]any)["hosts"].(map[string]any)["database"].(map[string]any)["ultra_postgres"] = map[string]any{"name": c.DBName, "user": c.DBUser, "password": c.DBPassword}
		if p.Secrets.DatabaseDumpFile != "" {
			dbvars := children["databases"].(map[string]any)["hosts"].(map[string]any)["database"].(map[string]any)
			archive, err := filepath.Abs(p.Secrets.DatabaseDumpFile)
			if err != nil {
				return err
			}
			scripts := filepath.Join(directory, "database-import")
			if err := os.MkdirAll(scripts, 0700); err != nil {
				return err
			}
			helper, err := recoveryassets.Scripts.ReadFile("database_dump_import.py")
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(scripts, "database_dump_import.py"), helper, 0600); err != nil {
				return err
			}
			dbvars["ultra_database_import_dump"] = archive
			dbvars["ultra_database_import_sha256"] = p.Secrets.DatabaseDumpSHA256
			dbvars["ultra_database_import_destination"] = "/var/lib/ultra-db-import/bootstrap.dump"
			dbvars["ultra_database_import_db"] = c.DBName
			dbvars["ultra_database_import_user"] = c.DBUser
			dbvars["ultra_database_import_password"] = c.DBPassword
			dbvars["ultra_database_import_script_directory"] = scripts
		}

	}
	if p.Bot.Enabled {
		src, err := binary(inspection["bridge"].Architecture, "bot")
		if err != nil {
			return err
		}
		sum, err := sourceSHA(src)
		if err != nil {
			return err
		}
		secrets, err := installplan.ReadSecretsFile(p.SecretsEnvFile())
		if err != nil {
			return err
		}
		projected, err := installplan.BotEnvironment(secrets)
		if err != nil {
			return err
		}
		bridge["ultra_bot_domain"] = p.Bot.Domain
		bridge["ultra_bot_port"] = p.Bot.Port
		bridge["ultra_bot_source"] = src
		bridge["ultra_bot_sha256"] = sum
		bridge["ultra_bot_environment"] = string(projected)
		if p.AdoptRuntime {
			oldBotEnvironment, readErr := inspection["bridge"].file("bot.env")
			if readErr != nil || len(oldBotEnvironment) == 0 {
				return fmt.Errorf("runtime adoption requires existing bot environment")
			}
			bridge["ultra_bot_environment"] = string(oldBotEnvironment)
		}
		oldEnvironment, err := inspection["bridge"].file("environment")
		if err != nil {
			return err
		}
		bridge["ultra_relay_environment"] = mergeBootstrapEnvironment(string(oldEnvironment), ds.BridgeEnv+fmt.Sprintf("ULTRA_BOT_DOMAIN=%s\nULTRA_BOT_PUBLIC_URL=https://%s\nULTRA_BOT_PORT=%d\nULTRA_BOT_TELEGRAM_SOCKS5=127.0.0.1:10809\n", p.Bot.Domain, p.PublicSubscriptionDomain(), p.Bot.Port))
		if p.AdoptRuntime {
			bridge["ultra_relay_environment"] = string(oldEnvironment)
		}
	}
	return nil
}

// Freeze the installed geo generation rather than resolving a newer release during adoption.
func preservedBootstrapGeoAssets(directory string, inspected []bootstrapGeoAsset) ([]map[string]any, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || len(inspected) != 2 {
		return nil, fmt.Errorf("runtime adoption requires known installed geo assets")
	}
	assets := make([]map[string]any, 0, 2)
	seen := map[string]bool{}
	for _, asset := range inspected {
		s := asset.Stat
		checksum, err := hex.DecodeString(s.Checksum)
		if (asset.Name != "geoip.dat" && asset.Name != "geosite.dat") || seen[asset.Name] ||
			s.Path != filepath.Join(directory, asset.Name) || !s.Exists || !s.Regular || s.Symlink || s.Size <= 0 ||
			err != nil || len(checksum) != sha256.Size {
			return nil, fmt.Errorf("runtime adoption requires verified installed geo assets")
		}
		seen[asset.Name] = true
		assets = append(assets, map[string]any{"name": asset.Name, "path": s.Path, "sha256": strings.ToLower(s.Checksum), "size": s.Size})
	}
	return assets, nil
}

func ensurePrivateBootstrapDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	identity, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 || !ok || identity.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("owned private bootstrap directory required")
	}
	return nil
}

// Freeze generated identities before the first mutating play. Retries adopt the
// exact original inputs even when the target was only partially configured.
func freezeBootstrapInventory(p *installplan.InstallPlan, inventory map[string]any, inspection map[string]bootstrapInspection, directory string) (map[string]any, error) {
	target := filepath.Join(directory, "inventory.frozen.json")
	read := func() (map[string]any, error) {
		info, err := os.Lstat(target)
		if err != nil {
			return nil, err
		}
		identity, ok := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || !ok || identity.Uid != uint32(os.Geteuid()) {
			return nil, fmt.Errorf("private frozen inventory required")
		}
		raw, err := os.ReadFile(target)
		if err != nil {
			return nil, err
		}
		var frozen map[string]any
		err = json.Unmarshal(raw, &frozen)
		if err == nil {
			if all, ok := frozen["all"].(map[string]any); ok {
				if vars, ok := all["vars"].(map[string]any); ok {
					if reused, ok := vars["ultra_reused_bridge"].(bool); ok {
						p.Bridge.ReuseSpec = reused
					}
				}
			}
		}
		return frozen, err
	}
	if _, err := os.Lstat(target); err == nil {
		return read()
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	options, err := bootstrapRenderOptions(p, inspection)
	if err != nil {
		return nil, err
	}
	inventory["all"].(map[string]any)["vars"].(map[string]any)["ultra_reused_bridge"] = p.Bridge.ReuseSpec
	desired, err := installplan.RenderDesiredStateWithOptions(p, options)
	if err != nil {
		return nil, err
	}
	if err = prepareBootstrapVariables(p, desired, inventory, inspection, directory); err != nil {
		return nil, err
	}
	if err = preserveAdoptionJSON(p, desired, inventory); err != nil {
		return nil, err
	}
	if err = prepareAdoptionBaseline(p, inventory, inspection); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(inventory)
	if err != nil {
		return nil, err
	}
	file, err := os.CreateTemp(directory, ".inventory-")
	if err != nil {
		return nil, err
	}
	name := file.Name()
	defer os.Remove(name) //nolint:errcheck
	if _, err = file.Write(raw); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	// Link provides create-if-absent semantics; concurrent preparations must
	// consume the winner rather than replacing its already generated keys.
	if err = os.Link(name, target); err != nil && !os.IsExist(err) {
		return nil, err
	}
	parent, err := os.Open(directory)
	if err != nil {
		return nil, err
	}
	err = parent.Sync()
	closeErr = parent.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return read()
}

// A retry resumes the active attempt. A new invocation after complete success
// inspects real targets again instead of trusting an old operation receipt.
func beginBootstrapAttempt(root string) (string, error) {
	journal := filepath.Join(root, "attempt.json")
	var state struct {
		Active   string `json:"active"`
		Complete bool   `json:"complete"`
	}
	if raw, err := os.ReadFile(journal); err == nil {
		info, err := os.Lstat(journal)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return "", fmt.Errorf("private attempt journal required")
		}
		if err = json.Unmarshal(raw, &state); err != nil {
			return "", err
		}
		if filepath.Base(state.Active) != state.Active || !strings.HasPrefix(state.Active, "attempt-") {
			return "", fmt.Errorf("invalid attempt identity")
		}
		if !state.Complete {
			directory := filepath.Join(root, state.Active)
			if err = ensurePrivateBootstrapDirectory(directory); err != nil {
				return "", err
			}
			return directory, nil
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	directory, err := os.MkdirTemp(root, "attempt-")
	if err != nil {
		return "", err
	}
	if err = saveBootstrapAttempt(journal, map[string]any{"active": filepath.Base(directory), "complete": false}); err != nil {
		return "", err
	}
	return directory, nil
}

func completeBootstrapAttempt(root, directory string) error {
	if filepath.Dir(directory) != root {
		return fmt.Errorf("invalid completed attempt")
	}
	return saveBootstrapAttempt(filepath.Join(root, "attempt.json"), map[string]any{"active": filepath.Base(directory), "complete": true})
}

func saveBootstrapAttempt(target string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(target), ".attempt-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name) //nolint:errcheck
	if _, err = file.Write(raw); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, target); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(target))
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr = directory.Close()
	if err != nil {
		return err
	}
	return closeErr
}

// Preserve unrelated runtime references while replacing only installer-owned keys.
func mergeBootstrapEnvironment(previous, desired string) string {
	owned := map[string]bool{"ULTRA_REPLICATION_KEY_FILE": true}
	for _, line := range strings.Split(desired, "\n") {
		key, _, ok := strings.Cut(line, "=")
		if ok {
			owned[strings.TrimSpace(key)] = true
		}
	}
	result := []string{}
	for _, line := range strings.Split(strings.TrimSuffix(previous, "\n"), "\n") {
		key, _, ok := strings.Cut(line, "=")
		if line != "" && (!ok || !owned[strings.TrimSpace(key)]) {
			result = append(result, line)
		}
	}
	result = append(result, strings.TrimSuffix(desired, "\n"))
	return strings.Join(result, "\n") + "\n"
}
