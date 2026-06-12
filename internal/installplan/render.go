package installplan

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"path"
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
		applyBridgeOverlay(bridgeSpec, opts.ExistingBridge)
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
	if p.Bot.Enabled {
		bridgeSpec.BotTelegramProxy = &config.BotTelegramProxySpec{Enabled: true}
	}
	if p.Features.DisableVLESSFlow {
		bridgeSpec.VLESSFlow = "none"
	} else {
		bridgeSpec.VLESSFlow = p.Features.VLESSFlow
	}
	var pgCfg *install.PostgresConfig
	var dbDSN string
	if p.Database.Enabled {
		primaryHost := p.Database.PrimaryHost
		if strings.TrimSpace(primaryHost) == "" {
			primaryHost = p.Bridge.SSHHost
		}
		replicaHost := p.Database.ReplicaHost
		if strings.TrimSpace(replicaHost) == "" && len(p.Exits) > 0 {
			replicaHost = p.Exits[0].SSHHost
		}
		bridgeHBA := p.Bridge.SSHHost
		if primaryHost == p.Bridge.SSHHost {
			bridgeHBA = "127.0.0.1"
		}
		pc := &install.PostgresConfig{
			DBName:      p.Database.Name,
			DBUser:      p.Database.User,
			BridgeHost:  bridgeHBA,
			ReplicaHost: replicaHost,
		}
		if err := pc.Defaults(); err != nil {
			return nil, err
		}
		pgCfg = pc
		dbHost := primaryHost
		if dbHost == p.Bridge.SSHHost {
			dbHost = "127.0.0.1"
		}
		dbDSN = pc.DSN(dbHost)
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

func applyBridgeOverlay(dst *config.Spec, src *config.Spec) {
	if src == nil {
		return
	}
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
	if src.SOCKS5 != nil {
		cpy := *src.SOCKS5
		if src.SOCKS5.UDP != nil {
			u := *src.SOCKS5.UDP
			cpy.UDP = &u
		}
		dst.SOCKS5 = &cpy
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
	return fmt.Errorf("render for bridge.reuse_spec=true requires reading the remote bridge spec; use the legacy apply path for now")
}
