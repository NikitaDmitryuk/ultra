package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// CurrentSpecSchemaVersion is bumped when JSON fields or semantics change incompatibly.
const CurrentSpecSchemaVersion = 1

// TunnelTLSProvision describes how the exit node obtained TLS credentials for bridge→exit splithttp.
// See deploy/TLS.md. Empty means unspecified (legacy configs).
type TunnelTLSProvision string

const (
	TunnelTLSACME       TunnelTLSProvision = "acme_letsencrypt"
	TunnelTLSUserProv   TunnelTLSProvision = "user_provided"
	TunnelTLSSelfSigned TunnelTLSProvision = "self_signed"
)

// Role selects bridge (outer) or exit (upstream-facing) node profile.
type Role string

const (
	RoleBridge Role = "bridge"
	RoleExit   Role = "exit"
)

// Routing modes for bridge SplitRouting (see Spec.RoutingMode).
const (
	RoutingModeBlocklist = "blocklist"
	RoutingModeRUDirect  = "ru_direct"
)

// FragmentSpec controls Xray sockopt.fragment on the bridge→exit outbound.
// Splitting the TLS ClientHello across multiple TCP packets prevents DPI from reading the SNI.
type FragmentSpec struct {
	// Packets selects which packets to fragment. "tlshello" targets only the TLS ClientHello.
	// Defaults to "tlshello".
	Packets string `json:"packets,omitempty"`
	// Length is the byte-range of each fragment, e.g. "100-200". Defaults to "100-200".
	Length string `json:"length,omitempty"`
	// Interval is the delay range between fragments in milliseconds, e.g. "10-20". Defaults to "10-20".
	Interval string `json:"interval,omitempty"`
}

// AntiCensorSpec groups optional DPI-evasion settings. All fields have safe defaults;
// the block may be omitted entirely and sensible values apply automatically.
type AntiCensorSpec struct {
	// Fragment enables TLS ClientHello fragmentation on the bridge→exit outbound.
	// When nil the feature is on with default parameters; set packets/length/interval to tune.
	// Set to &FragmentSpec{Packets:""} (empty packets) to disable fragmentation.
	Fragment *FragmentSpec `json:"fragment,omitempty"`

	// RealityFingerprints is the list of TLS client fingerprints to rotate randomly on each
	// Xray config build. Overrides reality.fingerprint when non-empty.
	// Defaults to ["chrome","firefox","safari","ios","android","randomized"].
	RealityFingerprints []string `json:"reality_fingerprints,omitempty"`

	// SplitHTTPMaxChunkKB limits each splithttp POST body in kilobytes (e.g. 64).
	// 0 = Xray default (≈1 MB). Smaller values disguise traffic patterns better.
	SplitHTTPMaxChunkKB int `json:"splithttp_max_chunk_kb,omitempty"`

	// SplitHTTPPadding adds random padding to each splithttp chunk.
	// Format: "min-max" bytes, e.g. "100-1000". Empty = no padding.
	SplitHTTPPadding string `json:"splithttp_padding,omitempty"`

	// ExitFallbackHost is the host:port the exit node forwards unrecognized TCP connections to
	// (active-probe defence). Defaults to the bridge REALITY dest (e.g. "www.yandex.ru:443").
	ExitFallbackHost string `json:"exit_fallback_host,omitempty"`

	// DisableDOH disables the built-in DNS over HTTPS resolver in Xray (default: DoH is enabled).
	// When false (default), Xray uses DoH servers to hide DNS queries from the local ISP.
	DisableDOH bool `json:"disable_doh,omitempty"`

	// WARPProxy routes all exit outbound traffic through a local Cloudflare WARP SOCKS5 proxy
	// on WARPProxyPort (default 40000). This changes the exit IP seen by destination servers
	// from the VPS datacenter IP to Cloudflare's IP pool.
	// Requires warp-cli to be installed and connected on the exit node.
	WARPProxy bool `json:"warp_proxy,omitempty"`

	// WARPProxyPort is the local port where warp-cli listens in proxy mode (default 40000).
	WARPProxyPort int `json:"warp_proxy_port,omitempty"`
}

// DatabaseSpec configures the PostgreSQL connection for user storage and traffic stats.
type DatabaseSpec struct {
	// DSN is a libpq-compatible connection string, e.g.:
	// "postgres://ultra:secret@db-host:5432/ultra_db?sslmode=require"
	DSN string `json:"dsn"`
}

// StatsSpec configures Xray in-process traffic stat collection.
type StatsSpec struct {
	// CollectIntervalSeconds is how often the collector polls Xray counters (default 60).
	CollectIntervalSeconds int `json:"collect_interval_seconds"`
	// APIListen is the loopback address for the Xray gRPC API inbound (default "127.0.0.1:10085").
	APIListen string `json:"api_listen"`
}

// Spec is relay deployment configuration (JSON file: -spec flag).
type Spec struct {
	// SchemaVersion defaults to 1 when zero (see Validate).
	SchemaVersion int `json:"schema_version"`

	Role        Role   `json:"role"`
	MimicPreset string `json:"mimic_preset"`

	// TunnelTLSProvision documents exit TLS provisioning for operators (optional).
	TunnelTLSProvision TunnelTLSProvision `json:"tunnel_tls_provision,omitempty"`

	ListenAddress string `json:"listen_address"`
	VLESSPort     int    `json:"vless_port"`

	AdminListen string `json:"admin_listen"` // e.g. 127.0.0.1:8443

	// PublicHost is the hostname or IP clients use to reach the bridge.
	PublicHost string `json:"public_host"`

	// DevMode uses cleartext TCP for the public inbound (local testing only).
	DevMode bool `json:"dev_mode"`

	Reality RealitySpec `json:"reality"`

	Exit ExitTunnelSpec `json:"exit"`

	// TLS for splithttp between bridge and exit (server cert on exit).
	SplitHTTPTLS SplitHTTPTLSSpec `json:"splithttp_tls"`

	// SplithttpPath must be identical on bridge and exit (set explicitly in production).
	// If empty, a path is taken from the mimic preset once per config build (fine for single-process tests only).
	SplithttpPath string `json:"splithttp_path"`

	// SplithttpHost is the HTTP Host header for splithttp (bridge→exit). When set, it overrides mimic.Strategy.Host()
	// so bridge and exit agree even if each process would otherwise instantiate the strategy differently.
	SplithttpHost string `json:"splithttp_host,omitempty"`

	// ExitCertPaths are required on the exit node when using TLS on splithttp inbound.
	ExitCertPaths CertPaths `json:"exit_cert"`

	// --- Bridge-only: split routing (geo rules: direct vs upstream exit) ---

	// SplitRouting selects whether the bridge uses geo-based path rules.
	// JSON null/omitted defaults to true (split on). Explicit false sends all traffic via exit (legacy).
	SplitRouting *bool `json:"split_routing,omitempty"`

	// GeoAssetsDir is the directory containing geoip.dat and geosite.dat (XRAY_LOCATION_ASSET).
	// Required on bridge when split routing is enabled (default).
	GeoAssetsDir string `json:"geo_assets_dir,omitempty"`

	// RoutingMode selects split policy when SplitRouting is true:
	//   "blocklist" — geosite/geoip/domain_exit → exit; everything else → direct (default).
	//   "ru_direct" — RU / private (geosite, geoip, optional TLD regex, domain_direct) → direct; everything else → exit.
	RoutingMode string `json:"routing_mode,omitempty"`

	// GeositeBlockTags are geosite.dat category names (no "geosite:" prefix) routed to blackhole when non-empty.
	// Prepended before other rules on the bridge; requires a block outbound in generated Xray JSON.
	GeositeBlockTags []string `json:"geosite_block_tags,omitempty"`

	// GeositeDirectTags (ru_direct only): categories (no "geosite:" prefix) sent to direct.
	// JSON null/omitted or []: no geosite direct rule (default; compatible with runetfreedom bundle).
	// Set e.g. ["ru"] only if your geosite.dat defines that code (v2fly full list, not guaranteed in runetfreedom).
	GeositeDirectTags []string `json:"geosite_direct_tags,omitempty"`

	// GeoipDirectTags (ru_direct only): geoip tags sent to direct. JSON null/omitted defaults to ["ru","private"].
	// Explicit empty array [] disables the geoip-based direct rule.
	GeoipDirectTags []string `json:"geoip_direct_tags,omitempty"`

	// RuDirectTLDRegex (ru_direct only): when true, append regexp matchers for .ru, .su, and .xn--p1ai (IDN .рф).
	// JSON null/omitted defaults to true.
	RuDirectTLDRegex *bool `json:"ru_direct_tld_regex,omitempty"`

	// GeositeExitTags are geosite.dat category names without the "geosite:" prefix, routed to exit in blocklist mode.
	// Empty defaults to a broad built-in tag list; narrower lists reduce matching cost.
	GeositeExitTags []string `json:"geosite_exit_tags,omitempty"`

	// GeoipExitTags are geoip.dat tags without the "geoip:" prefix, routed to exit in blocklist mode.
	GeoipExitTags []string `json:"geoip_exit_tags,omitempty"`

	// DomainExit are Xray domain matchers (e.g. "domain:example.com", "regexp:...") routed to exit (blocklist and ru_direct).
	DomainExit []string `json:"domain_exit,omitempty"`

	// DomainDirect are Xray domain matchers forced to direct, evaluated before other rules (blocklist and ru_direct).
	DomainDirect []string `json:"domain_direct,omitempty"`

	// XrayWire overrides tags and literals in generated Xray JSON (optional; see resolveXrayWire defaults).
	XrayWire *XrayWireSpec `json:"xray_wire,omitempty"`

	// SOCKS5 is an optional password SOCKS inbound on the bridge; same routing as VLESS when split_routing is on.
	SOCKS5 *BridgeSOCKS5Spec `json:"socks5,omitempty"`

	// Database configures the PostgreSQL backend for user storage and traffic stats (required on bridge).
	Database *DatabaseSpec `json:"database,omitempty"`

	// Stats configures Xray traffic stat collection. Requires Database to be set.
	Stats *StatsSpec `json:"stats,omitempty"`

	// AntiCensor groups optional DPI-evasion settings for the Russian TSPU and similar systems.
	// All fields have safe defaults; the block may be omitted entirely.
	AntiCensor *AntiCensorSpec `json:"anti_censor,omitempty"`
}

type RealitySpec struct {
	Dest        string   `json:"dest"`
	ServerNames []string `json:"server_names"`
	PrivateKey  string   `json:"private_key"`
	ShortIDs    []string `json:"short_ids"`
	PublicKey   string   `json:"public_key"`  // public key material for client export
	Fingerprint string   `json:"fingerprint"` // e.g. chrome
	SpiderX     string   `json:"spider_x"`    // optional path obfuscation, default "/"
}

type ExitTunnelSpec struct {
	Address    string `json:"address"`
	Port       int    `json:"port"`
	TunnelUUID string `json:"tunnel_uuid"` // shared tunnel identity bridge→exit
}

type SplitHTTPTLSSpec struct {
	ServerName  string   `json:"server_name"`
	Alpn        []string `json:"alpn"`
	Fingerprint string   `json:"fingerprint"`
}

type CertPaths struct {
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

// LoadSpec reads and validates a JSON spec file.
func LoadSpec(path string) (*Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Spec
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if err := s.requireGeoAssetFilesIfNeeded(); err != nil {
		return nil, err
	}
	return &s, nil
}

// requireGeoAssetFilesIfNeeded ensures geoip.dat and geosite.dat exist when loading a bridge spec from disk.
// Programmatic builds (e.g. ultra-install before SSH bootstrap) validate without this check.
func (s *Spec) requireGeoAssetFilesIfNeeded() error {
	if s.Role != RoleBridge || !s.SplitRoutingEnabled() {
		return nil
	}
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		p := filepath.Join(s.GeoAssetsDir, name)
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("config: geo asset %s: %w", name, err)
		}
	}
	return nil
}

// SplitRoutingEnabled returns the effective split-routing flag for the bridge.
// Omitted split_routing in JSON means true.
func (s *Spec) SplitRoutingEnabled() bool {
	if s.SplitRouting == nil {
		return true
	}
	return *s.SplitRouting
}

// BoolPtr returns a pointer to b (for specs/tests).
func BoolPtr(b bool) *bool {
	return &b
}

func (s *Spec) Validate() error {
	ver := s.SchemaVersion
	if ver == 0 {
		ver = 1
	}
	if ver != CurrentSpecSchemaVersion {
		return errors.New("config: unsupported schema_version (rebuild ultra-relay or migrate spec)")
	}
	if s.Role != RoleBridge && s.Role != RoleExit {
		return errors.New("config: role must be bridge or exit")
	}
	if s.TunnelTLSProvision != "" {
		allowed := []TunnelTLSProvision{TunnelTLSACME, TunnelTLSUserProv, TunnelTLSSelfSigned}
		if !slices.Contains(allowed, s.TunnelTLSProvision) {
			return errors.New("config: invalid tunnel_tls_provision")
		}
	}
	if s.VLESSPort <= 0 || s.VLESSPort > 65535 {
		return errors.New("config: invalid vless_port")
	}
	if s.ListenAddress == "" {
		s.ListenAddress = "0.0.0.0"
	}
	switch s.Role {
	case RoleBridge:
		if strings.TrimSpace(s.AdminListen) == "" {
			s.AdminListen = "127.0.0.1:8443"
		}
		if s.PublicHost == "" {
			return errors.New("config: bridge requires public_host for client export")
		}
		if !s.DevMode {
			if s.Reality.PrivateKey == "" || s.Reality.PublicKey == "" {
				return errors.New("config: bridge requires reality.private_key and reality.public_key unless dev_mode")
			}
			if len(s.Reality.ServerNames) == 0 || s.Reality.Dest == "" {
				return errors.New("config: bridge requires reality.dest and reality.server_names unless dev_mode")
			}
		}
		if s.Exit.Address == "" || s.Exit.Port <= 0 || s.Exit.TunnelUUID == "" {
			return errors.New("config: bridge requires exit.address, exit.port, exit.tunnel_uuid")
		}
		if s.SplitRoutingEnabled() {
			if s.GeoAssetsDir == "" {
				return errors.New("config: split_routing requires geo_assets_dir on bridge")
			}
			absGeo, err := filepath.Abs(s.GeoAssetsDir)
			if err != nil {
				return fmt.Errorf("config: geo_assets_dir: %w", err)
			}
			s.GeoAssetsDir = absGeo
			mode := s.RoutingMode
			if mode == "" {
				mode = RoutingModeBlocklist
			}
			if mode != RoutingModeBlocklist && mode != RoutingModeRUDirect {
				return errors.New("config: routing_mode must be blocklist or ru_direct when split_routing is set")
			}
		}
		if s.SOCKS5 != nil && s.SOCKS5.Enabled {
			if s.SOCKS5.Port <= 0 || s.SOCKS5.Port > 65535 {
				return errors.New("config: socks5.port must be 1..65535 when socks5.enabled")
			}
			if s.SOCKS5.Port == s.VLESSPort {
				return errors.New("config: socks5.port must differ from vless_port")
			}
			if strings.TrimSpace(s.SOCKS5.Username) == "" {
				return errors.New("config: socks5.username required when socks5.enabled")
			}
			if s.SOCKS5.Password == "" {
				return errors.New("config: socks5.password required when socks5.enabled")
			}
		}
	case RoleExit:
		if s.SOCKS5 != nil && s.SOCKS5.Enabled {
			return errors.New("config: socks5 is only valid on bridge role")
		}
		if s.Exit.TunnelUUID == "" {
			return errors.New("config: exit requires exit.tunnel_uuid for inbound tunnel")
		}
		if s.ExitCertPaths.CertFile == "" || s.ExitCertPaths.KeyFile == "" {
			return errors.New("config: exit requires exit_cert.cert_file and key_file")
		}
	}
	return nil
}
