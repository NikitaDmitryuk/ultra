package installplan

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path"
	"reflect"
	"strings"

	"github.com/xtls/xray-core/common/uuid"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/install"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/NikitaDmitryuk/ultra/internal/realitykey"
)

type DesiredState struct {
	BridgeSpec       []byte                  `json:"-"`
	ExitSpecs        map[string][]byte       `json:"-"`
	Bootstrap        []exits.BootstrapEntry  `json:"bootstrap"`
	BridgeEnv        string                  `json:"bridge_env"`
	ExitEnvs         map[string]string       `json:"exit_envs"`
	AdminToken       string                  `json:"admin_token"`
	TunnelUUIDs      map[string]string       `json:"tunnel_uuids"`
	SplitHTTPPath    string                  `json:"splithttp_path"`
	SplitHTTPHost    string                  `json:"splithttp_host"`
	DBDSN            string                  `json:"db_dsn,omitempty"`
	PostgresConfig   *install.PostgresConfig `json:"-"`
	BridgeSpecObject *config.Spec            `json:"-"`
	ExitSpecObjects  map[string]*config.Spec `json:"-"`
}

type RenderOptions struct {
	// PreserveRuntime is only for adoption of an explicitly reviewed installed
	// snapshot. Plan feature defaults must not reconfigure that snapshot.
	PreserveRuntime bool
	// Original JSON is required for PreserveRuntime: marshaling a Spec loses
	// unknown fields and explicit empty arrays with omitempty tags. Each raw
	// document must decode to its corresponding unmodified Existing spec.
	ExistingBridgeJSON []byte
	ExistingExitJSON   map[string][]byte
	ExistingExits      map[string]*config.Spec
	ExistingBridge     *config.Spec
	ExistingAdminToken string
	PriorBootstrap     []exits.BootstrapEntry
}

func RenderDesiredState(p *InstallPlan) (*DesiredState, error) {
	return RenderDesiredStateWithOptions(p, RenderOptions{})
}

func RenderDesiredStateWithOptions(p *InstallPlan, opts RenderOptions) (*DesiredState, error) {
	if err := ValidatePlan(p); err != nil {
		return nil, err
	}
	if opts.PreserveRuntime {
		return renderPreservedRuntime(p, opts)
	}
	if p.Bridge.ReuseSpec && opts.ExistingBridge == nil {
		return nil, errorsForReuseRender()
	}
	if p.Bridge.ReuseSpec && opts.ExistingBridge.Role != config.RoleBridge {
		return nil, fmt.Errorf("reuse bridge spec: existing spec role is not bridge")
	}
	preset := p.Features.Preset
	if p.Bridge.ReuseSpec && strings.TrimSpace(opts.ExistingBridge.MimicPreset) != "" {
		preset = opts.ExistingBridge.MimicPreset
	}
	strat, err := mimic.New(preset)
	if err != nil {
		return nil, err
	}
	mimicHost := strings.TrimSpace(p.Features.SplitHTTPHost)
	if mimicHost == "" {
		if p.Bridge.ReuseSpec {
			mimicHost = strings.TrimSpace(opts.ExistingBridge.SplithttpHost)
		}
		if mimicHost == "" {
			mimicHost = strat.Host()
		}
	}
	splitPath := strings.TrimSpace(p.Features.SplitHTTPPath)
	if splitPath == "" {
		if p.Bridge.ReuseSpec {
			splitPath = strings.TrimSpace(opts.ExistingBridge.SplithttpPath)
		}
		if splitPath == "" {
			splitPath = strat.NextPath()
		}
	}
	adminToken := strings.TrimSpace(opts.ExistingAdminToken)
	if adminToken == "" {
		var err error
		adminToken, err = randomHex(32)
		if err != nil {
			return nil, err
		}
	}
	tlsProv := config.TunnelTLSUserProv
	if p.Features.GenerateExitTLS {
		tlsProv = config.TunnelTLSSelfSigned
	}
	if p.Features.MainExitDomain != "" {
		tlsProv = config.TunnelTLSACME
	}
	var realitySpec config.RealitySpec
	if p.Bridge.ReuseSpec {
		realitySpec = opts.ExistingBridge.Reality
		if realitySpec.PrivateKey == "" || realitySpec.PublicKey == "" {
			return nil, fmt.Errorf("reuse bridge spec: existing spec missing reality key material")
		}
		if opts.ExistingBridge.TunnelTLSProvision != "" {
			tlsProv = opts.ExistingBridge.TunnelTLSProvision
		}
	} else {
		rk, err := realitykey.Generate()
		if err != nil {
			return nil, fmt.Errorf("reality keys: %w", err)
		}
		realitySNI := strings.TrimSpace(p.Bridge.RealitySNI)
		if realitySNI == "" {
			host, _, err := net.SplitHostPort(p.Bridge.RealityDest)
			if err != nil {
				host = p.Bridge.RealityDest
			}
			realitySNI = host
		}
		realitySpec = config.RealitySpec{
			Dest:        p.Bridge.RealityDest,
			ServerNames: []string{realitySNI},
			PrivateKey:  rk.PrivateKey,
			ShortIDs:    []string{""},
			PublicKey:   rk.PublicKey,
			SpiderX:     "/",
		}
	}
	splitTLS := config.SplitHTTPTLSSpec{}
	if p.Bridge.ReuseSpec {
		splitTLS = opts.ExistingBridge.SplitHTTPTLS
	}
	if splitTLS.ServerName == "" {
		splitTLS.ServerName = mimicHost
	}
	if len(splitTLS.Alpn) == 0 {
		splitTLS.Alpn = []string{"h2"}
	}
	if splitTLS.Fingerprint == "" {
		splitTLS.Fingerprint = "chrome"
	}
	tunnelIDs := make(map[string]string, len(p.Exits))
	for _, ex := range p.Exits {
		tunnelIDs[ex.Name] = resolveTunnelUUID(ex, opts.PriorBootstrap)
	}
	firstExit := p.Exits[0]
	firstUUID := tunnelIDs[firstExit.Name]
	bridgeSpec := &config.Spec{
		SchemaVersion:      config.CurrentSpecSchemaVersion,
		Role:               config.RoleBridge,
		MimicPreset:        strat.Name(),
		SplithttpHost:      mimicHost,
		TunnelTLSProvision: tlsProv,
		ListenAddress:      "0.0.0.0",
		VLESSPort:          p.Bridge.VLESSPort,
		AdminListen:        p.Bridge.AdminListen,
		PublicHost:         p.Bridge.PublicHost,
		Reality:            realitySpec,
		Exit: config.ExitTunnelSpec{
			Address:    firstExit.DialAddr,
			Port:       firstExit.Port,
			TunnelUUID: firstUUID,
		},
		SplithttpPath:   splitPath,
		SplitHTTPTLS:    splitTLS,
		TunnelTransport: config.TunnelTransport(p.Features.Transport),
		GeoAssetsDir:    path.Join(p.Bridge.RemoteDir, "geo"),
		GeositeExitTags: []string{"ru-blocked-all"},
	}
	if p.Bridge.ReuseSpec {
		if err := applyBridgeOverlay(bridgeSpec, opts.ExistingBridge); err != nil {
			return nil, err
		}
	}
	bridgeSpec.AntiCensor = buildAntiCensor(p, false)
	if p.Features.RoutingMode != "" {
		bridgeSpec.RoutingMode = p.Features.RoutingMode
	}
	if p.Features.GeositeBlockTags != "" {
		bridgeSpec.GeositeBlockTags = splitComma(p.Features.GeositeBlockTags)
	}
	if p.Features.DomainDirect != "" {
		bridgeSpec.DomainDirect = normalizeDomains(splitComma(p.Features.DomainDirect))
	}
	if p.Bot.Enabled || p.Features.BotTelegramProxy {
		bridgeSpec.BotTelegramProxy = &config.BotTelegramProxySpec{Enabled: true}
	}
	if p.Features.DisableVLESSFlow {
		bridgeSpec.VLESSFlow = "none"
	} else {
		bridgeSpec.VLESSFlow = p.Features.VLESSFlow
	}
	var credentialDSN string
	if p.Database.Enabled && p.Secrets.DatabaseCredentialsFile != "" {
		var err error
		credentialDSN, err = ReadDatabaseCredentials(p.Secrets.DatabaseCredentialsFile)
		if err != nil {
			return nil, err
		}
	}
	var pgCfg *install.PostgresConfig
	var dbDSN string
	if p.Bridge.ReuseSpec && opts.ExistingBridge.Database != nil && opts.ExistingBridge.Database.DSN != "" {
		// Keep the existing database identity and credentials during repeated installation.
		previous := *opts.ExistingBridge.Database
		bridgeSpec.Database = &previous
		dbDSN = previous.DSN
		if credentialDSN != "" && credentialDSN != previous.DSN {
			return nil, fmt.Errorf("database credentials file conflicts with existing bridge")
		}
		if p.Database.Enabled {
			u, err := url.Parse(previous.DSN)
			if err != nil || u.User == nil || u.Hostname() != "127.0.0.1" || u.Port() != "25432" ||
				strings.TrimPrefix(u.Path, "/") != p.Database.Name ||
				u.User.Username() != p.Database.User {
				return nil, fmt.Errorf("existing database must already use the dedicated DB tunnel; migrate explicitly before reuse")
			}
			password, ok := u.User.Password()
			if !ok || password == "" {
				return nil, fmt.Errorf("existing database credentials required")
			}
			pgCfg = &install.PostgresConfig{DBName: p.Database.Name, DBUser: p.Database.User, DBPassword: password, RepairExistingCredential: true, Port: 25432}
		}
	} else if p.Database.Enabled {
		pc := &install.PostgresConfig{DBName: p.Database.Name, DBUser: p.Database.User, Port: 25432}
		if credentialDSN != "" {
			u, err := url.Parse(credentialDSN)
			if err != nil || u.User == nil || u.Hostname() != "127.0.0.1" || u.Port() != "25432" || strings.TrimPrefix(u.Path, "/") != p.Database.Name || u.User.Username() != p.Database.User {
				return nil, fmt.Errorf("database credentials must match the configured dedicated database")
			}
			password, ok := u.User.Password()
			if !ok || password == "" {
				return nil, fmt.Errorf("database credentials file requires existing password")
			}
			pc.DBPassword = password
			pc.RepairExistingCredential = true
		}
		if p.Database.RepairAppCredentials {
			pc.RepairExistingCredential = true
		}
		if err := pc.Defaults(); err != nil {
			return nil, err
		}
		pgCfg = pc
		dbDSN = pc.DSN("127.0.0.1")
		bridgeSpec.Database = &config.DatabaseSpec{DSN: dbDSN}
		bridgeSpec.Stats = &config.StatsSpec{CollectIntervalSeconds: 60}
	}
	if err := bridgeSpec.Validate(); err != nil {
		return nil, fmt.Errorf("bridge spec: %w", err)
	}
	bridgeJSON, err := json.MarshalIndent(bridgeSpec, "", "  ")
	if err != nil {
		return nil, err
	}

	ds := &DesiredState{
		BridgeSpec:       bridgeJSON,
		ExitSpecs:        make(map[string][]byte, len(p.Exits)),
		BridgeEnv:        fmt.Sprintf("ULTRA_RELAY_ADMIN_TOKEN=%s\nULTRA_RELAY_LOG_LEVEL=%s\n", adminToken, p.Features.LogLevel),
		ExitEnvs:         make(map[string]string, len(p.Exits)),
		AdminToken:       adminToken,
		TunnelUUIDs:      make(map[string]string, len(p.Exits)),
		SplitHTTPPath:    splitPath,
		SplitHTTPHost:    mimicHost,
		DBDSN:            dbDSN,
		PostgresConfig:   pgCfg,
		BridgeSpecObject: bridgeSpec,
		ExitSpecObjects:  make(map[string]*config.Spec, len(p.Exits)),
	}
	if dbDSN != "" {
		ds.BridgeEnv += install.FormatDBEnvLine(dbDSN)
	}
	exitAnti := buildAntiCensor(p, true)
	for i, ex := range p.Exits {
		tid := tunnelIDs[ex.Name]
		name := ex.Name
		exitSpec := &config.Spec{
			SchemaVersion:      config.CurrentSpecSchemaVersion,
			Role:               config.RoleExit,
			MimicPreset:        strat.Name(),
			SplithttpHost:      mimicHost,
			TunnelTLSProvision: tlsProv,
			ListenAddress:      "0.0.0.0",
			VLESSPort:          ex.Port,
			Exit: config.ExitTunnelSpec{
				TunnelUUID: tid,
			},
			SplithttpPath:   splitPath,
			SplitHTTPTLS:    splitTLS,
			TunnelTransport: config.TunnelTransport(p.Features.Transport),
			ExitCertPaths: config.CertPaths{
				CertFile: path.Join(p.Bridge.RemoteDir, "fullchain.pem"),
				KeyFile:  path.Join(p.Bridge.RemoteDir, "privkey.pem"),
			},
			AntiCensor: exitAnti,
		}
		if err := exitSpec.Validate(); err != nil {
			return nil, fmt.Errorf("exit spec %s: %w", name, err)
		}
		b, err := json.MarshalIndent(exitSpec, "", "  ")
		if err != nil {
			return nil, err
		}
		ds.ExitSpecs[name] = b
		ds.ExitSpecObjects[name] = exitSpec
		ds.ExitEnvs[name] = fmt.Sprintf("ULTRA_RELAY_LOG_LEVEL=%s\n", p.Features.LogLevel)
		ds.TunnelUUIDs[name] = tid
		enabled := true
		if ex.Enabled != nil {
			enabled = *ex.Enabled
		}
		ds.Bootstrap = append(ds.Bootstrap, exits.BootstrapEntry{
			Name:       name,
			Address:    ex.DialAddr,
			Port:       ex.Port,
			TunnelUUID: tid,
			Priority:   ex.Priority,
			Enabled:    exits.BootstrapEnabledPtr(enabled),
		})
		if i == 0 {
			ds.TunnelUUIDs["primary"] = tid
		}
	}
	return ds, nil
}

// renderPreservedRuntime adopts the inspected snapshot, rather than treating
// installer defaults as requested runtime changes. Validation uses a separate
// copy because Spec.Validate fills defaults that were absent from the snapshot.
func renderPreservedRuntime(p *InstallPlan, opts RenderOptions) (*DesiredState, error) {
	if !p.Bridge.ReuseSpec || opts.ExistingBridge == nil || strings.TrimSpace(opts.ExistingAdminToken) == "" {
		return nil, fmt.Errorf("adoption requires existing bridge specification and admin identity")
	}
	clone := func(src *config.Spec, raw []byte, role config.Role) (*config.Spec, []byte, error) {
		if src == nil || src.Role != role {
			return nil, nil, fmt.Errorf("adoption requires existing %s specification", role)
		}
		if len(raw) == 0 {
			return nil, nil, fmt.Errorf("adoption requires original existing %s JSON", role)
		}
		var checked, preserved config.Spec
		if err := json.Unmarshal(raw, &preserved); err != nil {
			return nil, nil, fmt.Errorf("adoption existing %s JSON: %w", role, err)
		}
		if !reflect.DeepEqual(&preserved, src) {
			return nil, nil, fmt.Errorf("adoption existing %s JSON does not match reviewed specification", role)
		}
		if err := json.Unmarshal(raw, &checked); err != nil {
			return nil, nil, err
		}
		if err := checked.Validate(); err != nil {
			return nil, nil, fmt.Errorf("adoption existing %s specification: %w", role, err)
		}
		raw = append([]byte(nil), raw...)
		return &preserved, raw, nil
	}
	bridge, raw, err := clone(opts.ExistingBridge, opts.ExistingBridgeJSON, config.RoleBridge)
	if err != nil {
		return nil, err
	}
	if len(opts.PriorBootstrap) == 0 {
		return nil, fmt.Errorf("adoption requires existing bootstrap topology")
	}
	routes := make(map[string]exits.BootstrapEntry, len(opts.PriorBootstrap))
	names := make(map[string]bool, len(opts.PriorBootstrap))
	for _, entry := range opts.PriorBootstrap {
		key := net.JoinHostPort(entry.Address, fmt.Sprint(entry.Port))
		if strings.TrimSpace(entry.Name) == "" || strings.TrimSpace(entry.Address) == "" || entry.Port <= 0 || entry.Port > 65535 ||
			strings.TrimSpace(entry.TunnelUUID) == "" ||
			names[entry.Name] {
			return nil, fmt.Errorf("adoption existing bootstrap topology is invalid")
		}
		if _, exists := routes[key]; exists {
			return nil, fmt.Errorf("adoption existing bootstrap topology has duplicate route")
		}
		routes[key] = entry
		names[entry.Name] = true
	}
	active, ok := routes[net.JoinHostPort(bridge.Exit.Address, fmt.Sprint(bridge.Exit.Port))]
	if !ok || active.TunnelUUID != bridge.Exit.TunnelUUID {
		return nil, fmt.Errorf("adoption bridge exit does not match existing bootstrap topology")
	}
	ds := &DesiredState{
		BridgeSpec: raw, BridgeSpecObject: bridge, AdminToken: opts.ExistingAdminToken,
		ExitSpecs: make(map[string][]byte, len(p.Exits)), ExitSpecObjects: make(map[string]*config.Spec, len(p.Exits)),
		ExitEnvs: make(map[string]string, len(p.Exits)), TunnelUUIDs: make(map[string]string, len(p.Exits)),
		SplitHTTPPath: bridge.SplithttpPath, SplitHTTPHost: bridge.SplithttpHost,
	}
	if bridge.Database != nil {
		ds.DBDSN = bridge.Database.DSN
	}
	for _, entry := range opts.PriorBootstrap {
		if entry.Enabled != nil {
			entry.Enabled = exits.BootstrapEnabledPtr(*entry.Enabled)
		}
		ds.Bootstrap = append(ds.Bootstrap, entry)
	}
	for _, ex := range p.Exits {
		exit, raw, err := clone(opts.ExistingExits[ex.Name], opts.ExistingExitJSON[ex.Name], config.RoleExit)
		if err != nil {
			return nil, err
		}
		if exit.ExitCertPaths.CertFile != "/etc/ultra-relay/fullchain.pem" || exit.ExitCertPaths.KeyFile != "/etc/ultra-relay/privkey.pem" {
			return nil, fmt.Errorf("adoption requires canonical existing exit certificate paths")
		}
		entry, ok := routes[net.JoinHostPort(ex.DialAddr, fmt.Sprint(ex.Port))]
		if !ok || exit.VLESSPort != ex.Port || entry.TunnelUUID != exit.Exit.TunnelUUID ||
			(ex.TunnelUUID != "" && ex.TunnelUUID != entry.TunnelUUID) {
			return nil, fmt.Errorf("adoption static exit does not match existing bootstrap topology")
		}
		ds.ExitSpecs[ex.Name] = raw
		ds.ExitSpecObjects[ex.Name] = exit
		ds.TunnelUUIDs[ex.Name] = entry.TunnelUUID
	}
	return ds, nil
}

func MarshalBootstrap(entries []exits.BootstrapEntry) ([]byte, error) {
	return json.MarshalIndent(entries, "", "  ")
}

func tunnelUUID(ex ExitNode) string {
	if strings.TrimSpace(ex.TunnelUUID) != "" {
		return strings.TrimSpace(ex.TunnelUUID)
	}
	id := uuid.New()
	return (&id).String()
}

func resolveTunnelUUID(ex ExitNode, prior []exits.BootstrapEntry) string {
	if strings.TrimSpace(ex.TunnelUUID) != "" {
		return strings.TrimSpace(ex.TunnelUUID)
	}
	if u := exits.BootstrapTunnelUUID(prior, ex.DialAddr, ex.Port); u != "" {
		return u
	}
	return tunnelUUID(ex)
}

func applyBridgeOverlay(dst *config.Spec, src *config.Spec) error {
	if src == nil {
		return nil
	}
	raw, err := json.Marshal(src)
	if err != nil {
		return err
	}
	var previous config.Spec
	if err = json.Unmarshal(raw, &previous); err != nil {
		return err
	}
	src = &previous
	dst.PublicEntries = src.PublicEntries
	dst.HappDefaultJSON = src.HappDefaultJSON
	dst.SubscriptionPreviewBridges = src.SubscriptionPreviewBridges
	dst.ProbeURLs = src.ProbeURLs
	dst.Stats = src.Stats
	dst.SubscriptionBridges = append([]config.SubscriptionBridge(nil), src.SubscriptionBridges...)
	dst.PrimaryXHTTP = src.PrimaryXHTTP
	dst.LegacyPublicEnabled = src.LegacyPublicEnabled
	dst.ExperimentalProfileFile = src.ExperimentalProfileFile
	dst.GatewayVLESSPort = src.GatewayVLESSPort
	dst.PublicXHTTPTLS = src.PublicXHTTPTLS
	if g := strings.TrimSpace(src.GeoAssetsDir); g != "" {
		dst.GeoAssetsDir = g
	}
	if len(src.GeositeExitTags) > 0 {
		dst.GeositeExitTags = append([]string(nil), src.GeositeExitTags...)
	}
	if len(src.GeoipExitTags) > 0 {
		dst.GeoipExitTags = append([]string(nil), src.GeoipExitTags...)
	}
	if len(src.DomainDirect) > 0 {
		dst.DomainDirect = append([]string(nil), src.DomainDirect...)
	}
	if len(src.DomainExit) > 0 {
		dst.DomainExit = append([]string(nil), src.DomainExit...)
	}
	if rm := strings.TrimSpace(src.RoutingMode); rm != "" {
		dst.RoutingMode = rm
	}
	if src.SplitRouting != nil {
		v := *src.SplitRouting
		dst.SplitRouting = &v
	}
	if src.XrayWire != nil {
		cpy := *src.XrayWire
		if len(src.XrayWire.SniffingDestOverride) > 0 {
			cpy.SniffingDestOverride = append([]string(nil), src.XrayWire.SniffingDestOverride...)
		}
		dst.XrayWire = &cpy
	}

	if src.BotTelegramProxy != nil {
		cpy := *src.BotTelegramProxy
		dst.BotTelegramProxy = &cpy
	}
	if len(src.GeositeBlockTags) > 0 {
		dst.GeositeBlockTags = append([]string(nil), src.GeositeBlockTags...)
	}
	if src.GeositeDirectTags != nil {
		dst.GeositeDirectTags = append([]string(nil), src.GeositeDirectTags...)
	}
	if src.GeoipDirectTags != nil {
		dst.GeoipDirectTags = append([]string(nil), src.GeoipDirectTags...)
	}
	if src.RuDirectTLDRegex != nil {
		v := *src.RuDirectTLDRegex
		dst.RuDirectTLDRegex = &v
	}
	return nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func buildAntiCensor(p *InstallPlan, exit bool) *config.AntiCensorSpec {
	a := &config.AntiCensorSpec{
		Profile:             p.Features.AntiCensorProfile,
		DisableDOH:          p.Features.DisableDOH,
		SplitHTTPPadding:    p.Features.SplitHTTPPadding,
		SplitHTTPMaxChunkKB: p.Features.SplitHTTPMaxChunkKB,
	}
	if !exit {
		a.PublicXHTTPPort = p.Features.PublicXHTTPPort
		if p.Features.DisableFragment {
			a.Fragment = &config.FragmentSpec{Packets: ""}
		}
		if p.Features.RealityFingerprintsCSV != "" {
			a.RealityFingerprints = splitComma(p.Features.RealityFingerprintsCSV)
		}
	}
	if exit && p.Features.WARP {
		a.WARPProxy = true
		a.WARPProxyPort = p.Features.WARPPort
	}
	return a
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func normalizeDomains(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if strings.Contains(item, ":") {
			out = append(out, item)
		} else {
			out = append(out, "domain:"+item)
		}
	}
	return out
}

func errorsForReuseRender() error {
	return fmt.Errorf(
		"render for bridge.reuse_spec=true requires reading the remote bridge spec; use apply with read-only Ansible target inspection",
	)
}
