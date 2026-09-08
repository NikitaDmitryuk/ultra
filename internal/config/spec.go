package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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

// TunnelTransport selects the transport protocol for the bridge→exit internal tunnel.
// Empty/omitted defaults to splithttp (backward compatible).
type TunnelTransport string

const (
	TunnelTransportSplitHTTP TunnelTransport = "splithttp"
	TunnelTransportGRPC      TunnelTransport = "grpc"
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

const (
	AntiCensorProfileFast     = "fast"
	AntiCensorProfileBalanced = "balanced"
	AntiCensorProfileStealth  = "stealth"
)

// FragmentSpec controls the opt-in freedom fragment outbound for bridge→exit.
// Splitting the TLS ClientHello across multiple TCP packets obfuscates the SNI field.
type FragmentSpec struct {
	// Packets selects which packets to fragment. "tlshello" targets only the TLS ClientHello.
	// Defaults to "tlshello".
	Packets string `json:"packets,omitempty"`
	// Length is the byte-range of each fragment, e.g. "100-200". Defaults to "100-200".
	Length string `json:"length,omitempty"`
	// Interval is the delay range between fragments in milliseconds, e.g. "10-20". Defaults to "10-20".
	Interval string `json:"interval,omitempty"`
}

// AntiCensorSpec groups optional connection tuning settings. All fields have safe defaults;
// the block may be omitted entirely and sensible values apply automatically.
type AntiCensorSpec struct {
	// Profile selects a coarse anti-censorship tuning profile. Empty defaults to "balanced".
	// The legacy public TCP REALITY client profile remains unchanged by this setting.
	Profile string `json:"profile,omitempty"`

	// PublicXHTTPPort enables an additional public VLESS+REALITY+XHTTP inbound on the bridge
	// for the fallback_xhttp_reality client profile. 0 disables this optional profile.
	PublicXHTTPPort int `json:"public_xhttp_port,omitempty"`

	// Fragment enables TLS ClientHello fragmentation on the bridge→exit outbound.
	// Nil disables fragmentation; an explicit packets value enables it.
	// Set to &FragmentSpec{Packets:""} (empty packets) to disable fragmentation.
	Fragment *FragmentSpec `json:"fragment,omitempty"`

	// RealityFingerprints supplies the first fingerprint if reality.fingerprint is absent.
	// The default client fingerprint is chrome; server reload does not rotate ClientHello.
	RealityFingerprints []string `json:"reality_fingerprints,omitempty"`

	// SplitHTTPMaxChunkKB limits each splithttp POST body in kilobytes (e.g. 64).
	// 0 = Xray default (≈1 MB). Smaller values disguise traffic patterns better.
	SplitHTTPMaxChunkKB int `json:"splithttp_max_chunk_kb,omitempty"`

	// SplitHTTPPadding adds random padding to each splithttp chunk.
	// Positive min-max range. Empty and legacy zero ranges use the core default 100-1000.
	SplitHTTPPadding string `json:"splithttp_padding,omitempty"`

	// ExitFallbackHost is the host:port the exit node forwards unrecognized TCP connections to
	// (active-probe defence). Defaults to the bridge REALITY dest (e.g. "www.yandex.ru:443").
	ExitFallbackHost string `json:"exit_fallback_host,omitempty"`

	// DisableDOH disables the built-in DNS over HTTPS resolver in Xray (default: DoH is enabled).
	// When false (default), Xray uses DoH servers to hide DNS queries from the local ISP.
	DisableDOH bool `json:"disable_doh,omitempty"`

	// GRPCInitialWindowSize is the HTTP/2 per-stream flow-control window size in bytes for the
	// gRPC bridge→exit tunnel (default 4 MiB). Increase if upload latency under load is high;
	// decrease only to reduce memory usage per connection.
	GRPCInitialWindowSize int `json:"grpc_initial_window_size,omitempty"`

	// WARPProxy routes all exit outbound traffic through a local Cloudflare WARP SOCKS5 proxy
	// on WARPProxyPort (default 40000). This changes the exit IP seen by destination servers
	// from the VPS datacenter IP to Cloudflare's IP pool.
	// Requires warp-cli to be installed and connected on the exit node.
	WARPProxy bool `json:"warp_proxy,omitempty"`

	// WARPProxyPort is the local port where warp-cli listens in proxy mode (default 40000).
	WARPProxyPort int `json:"warp_proxy_port,omitempty"`

	// WARPDirectDomains bypasses WARP for these exact destination domains on the exit.
	WARPDirectDomains []string `json:"warp_direct_domains,omitempty"`
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
	SchemaVersion  int                 `json:"schema_version"`
	ProbeURLs      []string            `json:"probe_urls,omitempty"`
	PublicXHTTPTLS *PublicXHTTPTLSSpec `json:"public_xhttp_tls,omitempty"`
	PublicEntries  []PublicEntry       `json:"public_entries,omitempty"`

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

	// VLESSFlow sets flow on the public REALITY inbound and client exports (default xtls-rprx-vision).
	// Use "none" to disable flow (legacy clients; Xray 26 deprecation warnings remain).
	VLESSFlow string `json:"vless_flow,omitempty"`

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

	// TunnelTransport selects bridge→exit tunnel transport: "splithttp" (default) or "grpc".
	// Must be identical on bridge and exit. Empty defaults to splithttp.
	TunnelTransport TunnelTransport `json:"tunnel_transport,omitempty"`

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

	// BotTelegramProxy is a local SOCKS5 inbound for ultra-bot Telegram API traffic (routed to active exit).
	BotTelegramProxy *BotTelegramProxySpec `json:"bot_telegram_proxy,omitempty"`

	// Database configures the PostgreSQL backend for user storage and traffic stats (required on bridge).
	Database *DatabaseSpec `json:"database,omitempty"`

	// Stats configures Xray traffic stat collection. Requires Database to be set.
	Stats *StatsSpec `json:"stats,omitempty"`

	// AntiCensor groups optional connection tuning settings.
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
	// PinnedPeerCertSHA256 is the exit leaf cert SHA-256 (hex, no colons) for bridge→exit TLS when self_signed.
	PinnedPeerCertSHA256 string `json:"pinned_peer_cert_sha256,omitempty"`
}

type SplitHTTPTLSSpec struct {
	// OmitSNI is permitted only for IP-addressed tunnels with pinned leaf certificates.
	OmitSNI     bool     `json:"omit_sni,omitempty"`
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

// UsesGRPC reports whether the bridge→exit tunnel is configured to use gRPC transport.
func (s *Spec) UsesGRPC() bool { return s.TunnelTransport == TunnelTransportGRPC }

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
	if err := s.validateTransportExtensions(); err != nil {
		return err
	}
	for _, target := range s.ProbeURLs {
		u, err := url.Parse(target)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
			return errors.New("probe_urls must be HTTPS URLs without credentials")
		}
	}
	if len(s.ProbeURLs) != 0 && len(s.ProbeURLs) != 2 {
		return errors.New("probe_urls requires two independent HTTPS targets")
	}

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
			if s.SOCKS5.PortRangeStart == 0 {
				s.SOCKS5.PortRangeStart = 10810
			}
			if s.SOCKS5.PortRangeEnd == 0 {
				s.SOCKS5.PortRangeEnd = 10899
			}
			if s.SOCKS5.PortRangeStart < 1 || s.SOCKS5.PortRangeEnd > 65535 ||
				s.SOCKS5.PortRangeStart > s.SOCKS5.PortRangeEnd {
				return errors.New("config: socks5.port_range_start/end invalid")
			}
			if s.SOCKS5.Port >= s.SOCKS5.PortRangeStart && s.SOCKS5.Port <= s.SOCKS5.PortRangeEnd {
				return errors.New("config: socks5.port must not fall inside socks5.port_range (reserved for per-client inbounds)")
			}
		}
		if s.BotTelegramProxy != nil && s.BotTelegramProxy.Enabled {
			port := botTelegramProxyPort(s.BotTelegramProxy)
			if port == s.VLESSPort {
				return errors.New("config: bot_telegram_proxy.port must differ from vless_port")
			}
			if port == HealthProbePort {
				return errors.New("config: bot_telegram_proxy.port conflicts with health probe port")
			}
			if s.SOCKS5 != nil && s.SOCKS5.Enabled && port == s.SOCKS5.Port {
				return errors.New("config: bot_telegram_proxy.port must differ from socks5.port")
			}
		}
		if s.AntiCensor != nil {
			profile := strings.TrimSpace(s.AntiCensor.Profile)
			if profile != "" && profile != AntiCensorProfileFast && profile != AntiCensorProfileBalanced &&
				profile != AntiCensorProfileStealth {
				return errors.New("config: anti_censor.profile must be fast, balanced, or stealth")
			}
			if p := s.AntiCensor.PublicXHTTPPort; p < 0 || p > 65535 {
				return errors.New("config: anti_censor.public_xhttp_port must be 0..65535")
			} else if p > 0 {
				if p == s.VLESSPort {
					return errors.New("config: anti_censor.public_xhttp_port must differ from vless_port")
				}
				if _, adminPort, err := net.SplitHostPort(s.AdminListen); err == nil && adminPort != "" {
					if adminPort == fmt.Sprint(p) {
						return errors.New("config: anti_censor.public_xhttp_port must differ from admin_listen port")
					}
				}
				if p == HealthProbePort {
					return errors.New("config: anti_censor.public_xhttp_port conflicts with health probe port")
				}
				if s.SOCKS5 != nil && s.SOCKS5.Enabled && p == s.SOCKS5.Port {
					return errors.New("config: anti_censor.public_xhttp_port must differ from socks5.port")
				}
				if s.BotTelegramProxy != nil && s.BotTelegramProxy.Enabled && p == botTelegramProxyPort(s.BotTelegramProxy) {
					return errors.New("config: anti_censor.public_xhttp_port must differ from bot_telegram_proxy.port")
				}
			}
		}
	case RoleExit:
		if s.SOCKS5 != nil && s.SOCKS5.Enabled {
			return errors.New("config: socks5 is only valid on bridge role")
		}
		if s.BotTelegramProxy != nil && s.BotTelegramProxy.Enabled {
			return errors.New("config: bot_telegram_proxy is only valid on bridge role")
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

// HealthTargets are fetched through each exit, never through a direct fallback.
func (s *Spec) HealthTargets() []string {
	if len(s.ProbeURLs) > 0 {
		return s.ProbeURLs
	}
	return []string{"https://speed.cloudflare.com/__down?bytes=65536", "https://httpbingo.org/bytes/65536"}
}

func effectivePadding(s *Spec) string {
	if s.AntiCensor == nil {
		return "100-1000"
	}
	p := s.AntiCensor.SplitHTTPPadding
	switch p {
	case "", "0", "0-100", "0-64", "0-128":
		return "100-1000"
	}
	return p
}
func (s *Spec) validateTransportExtensions() error {
	if s.Role != RoleBridge && (s.PublicXHTTPTLS != nil || len(s.PublicEntries) > 0) {
		return errors.New("public listeners and entries require bridge role")
	}
	ids := map[string]bool{"primary": true}
	for _, entry := range s.PublicEntries {
		if entry.ID == "" || strings.ContainsAny(entry.ID, "/ \t\n") || ids[entry.ID] || entry.Host == "" || strings.ContainsAny(entry.Host, "/@?# \t\r\n") || entry.TCPPort < 1 || entry.TCPPort > 65535 {
			return errors.New("invalid or duplicate public entry")
		}
		ids[entry.ID] = true
		if entry.XHTTPRealityPort < 0 || entry.XHTTPRealityPort > 65535 || entry.XHTTPTLSPort < 0 || entry.XHTTPTLSPort > 65535 {
			return errors.New("invalid entry port")
		}
		if entry.XHTTPRealityPort > 0 && (s.AntiCensor == nil || s.AntiCensor.PublicXHTTPPort == 0) {
			return errors.New("entry requires existing XHTTP REALITY listener")
		}
		if entry.XHTTPTLSPort > 0 && s.PublicXHTTPTLS == nil {
			return errors.New("entry requires existing XHTTP TLS listener")
		}
	}
	p := effectivePadding(s)
	parts := strings.Split(p, "-")
	if len(parts) > 2 {
		return errors.New("invalid splithttp_padding")
	}
	lo, e := strconv.Atoi(parts[0])
	hi := lo
	if len(parts) == 2 {
		var err error
		hi, err = strconv.Atoi(parts[1])
		if err != nil {
			return errors.New("invalid splithttp_padding")
		}
	}
	if e != nil || lo <= 0 || hi < lo || hi > 65536 {
		return errors.New("splithttp_padding must be a positive range up to 65536 bytes")
	}
	if lo > 100 || hi < 1000 {
		return errors.New("splithttp_padding must include 100-1000 for compatibility with issued Xray profiles")
	}
	if s.AntiCensor != nil && s.AntiCensor.SplitHTTPPadding != "" && s.AntiCensor.SplitHTTPPadding != p {
		slog.Warn("legacy padding normalized to Xray default; issued profiles remain compatible")
	}
	if t := s.PublicXHTTPTLS; t != nil {
		if t.Port <= 0 || t.Port > 65535 || t.Port == s.VLESSPort || (s.AntiCensor != nil && t.Port == s.AntiCensor.PublicXHTTPPort) {
			return errors.New("public_xhttp_tls requires a distinct port")
		}
		if _, p, err := net.SplitHostPort(s.AdminListen); err == nil && p == strconv.Itoa(t.Port) {
			return errors.New("public_xhttp_tls conflicts with admin port")
		}
		if t.Port == HealthProbePort || (s.SOCKS5 != nil && s.SOCKS5.Enabled && t.Port == s.SOCKS5.Port) {
			return errors.New("public_xhttp_tls conflicts with an existing listener")
		}
		if t.ServerName == "" || strings.ContainsAny(t.ServerName, "/: \t\r\n") || net.ParseIP(t.ServerName) != nil || t.CertificateFile == "" || t.KeyFile == "" {
			return errors.New("public_xhttp_tls requires server_name, certificate_file and key_file")
		}
		if t.Mode != "" && t.Mode != "stream-up" && t.Mode != "packet-up" {
			return errors.New("public_xhttp_tls mode must be stream-up or packet-up")
		}
		if t.Path == "" || !strings.HasPrefix(t.Path, "/") {
			return errors.New("public_xhttp_tls requires absolute HTTP path")
		}
		if d := t.Download; d != nil {
			if d.Address == "" || d.ServerName == "" || d.Port <= 0 || d.Port > 65535 {
				return errors.New("invalid XHTTP download endpoint")
			}
		}
	}
	return nil
}
