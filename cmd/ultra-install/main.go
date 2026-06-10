// Command ultra-install builds paired bridge/exit specs and can install them over SSH (key auth only).
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/xtls/xray-core/common/uuid"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/install"
	"github.com/NikitaDmitryuk/ultra/internal/loglevel"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/NikitaDmitryuk/ultra/internal/realitykey"
)

func splitCommaNonEmpty(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// realityServerNames builds inbound server_names; sni defaults to the host part of dest.
func realityServerNames(dest, sni string) []string {
	if strings.TrimSpace(sni) != "" {
		return []string{sni}
	}
	host, _, err := net.SplitHostPort(dest)
	if err != nil {
		host = dest
	}
	return []string{host}
}

func main() {
	bridgeHost := flag.String("bridge", "", "bridge VPS hostname or IP (SSH target)")
	exitHost := flag.String("exit", "", "exit VPS hostname or IP (SSH target)")

	// PostgreSQL flags
	dbHost := flag.String("db-host", "", "host to install PostgreSQL primary on (default: same as -bridge)")
	dbReplica := flag.String(
		"db-replica",
		"",
		"host to install PostgreSQL streaming replica on (default: same as -exit); requires -db-host",
	)
	dbSSHUser := flag.String("db-ssh-user", "", "SSH user for DB hosts (default: same as -ssh-user)")
	dbName := flag.String("db-name", "ultra_db", "PostgreSQL database name")
	dbUser := flag.String("db-user", "ultra", "PostgreSQL application role")
	exitDial := flag.String(
		"exit-dial",
		"",
		"hostname or IP for bridge→exit splithttp dial in spec (default: same as -exit); use DNS name when dial by IP breaks Host validation",
	)
	exit2Host := flag.String("exit2", "", "optional second exit VPS for failover (same install as -exit)")
	exit2Dial := flag.String(
		"exit2-dial",
		"",
		"bridge dial address for -exit2 (default: same as -exit2)",
	)
	exit2Priority := flag.Int("exit2-priority", 200, "failover priority for -exit2 (lower = preferred; primary -exit uses 100)")
	exit2Name := flag.String("exit2-name", "backup", "display name for -exit2 in PostgreSQL exit_nodes")
	sshUser := flag.String("ssh-user", "root", "SSH user (key auth; avoid password automation)")
	identity := flag.String("identity", "", "path to SSH private key (optional if ssh uses agent)")
	publicHost := flag.String("public-host", "", "hostname or IP clients use to reach the bridge (default: -bridge)")
	preset := flag.String("preset", "apijson", "splithttp template: apijson, steamlike (plusgaming = apijson)")
	splithttpHostFlag := flag.String(
		"splithttp-host",
		"",
		"override spec splithttp_host and tunnel TLS server name / cert CN (default: preset default host)",
	)
	splithttpPathFlag := flag.String(
		"splithttp-path",
		"",
		"override spec splithttp_path (default: random path from preset at install time)",
	)
	realityDest := flag.String(
		"reality-dest",
		"",
		"public TLS handshake target host:port for the front inbound (required unless -reuse-bridge-spec)",
	)
	realitySNI := flag.String("reality-sni", "", "TLS server name for that handshake (default: host from -reality-dest)")
	vlessPort := flag.Int("vless-port", 443, "TCP port: public client listener on the bridge")
	tunnelPort := flag.Int(
		"tunnel-port",
		0,
		"TCP port on exit for bridge→exit splithttp; 0 means same as -vless-port (legacy single-port setup)",
	)
	remoteDir := flag.String("remote-dir", "/etc/ultra-relay", "remote config directory")
	projectRoot := flag.String("project-root", ".", "repo root (for systemd unit template)")
	binaryPath := flag.String("binary", "ultra-relay-linux-amd64", "local ultra-relay binary to upload")
	dryRun := flag.Bool("dry-run", false, "print specs and secrets to stdout; do not SSH")
	generateExitTLS := flag.Bool("generate-exit-tls", true, "on exit: openssl self-signed cert for mimic host (see deploy/TLS.md)")
	writeLocal := flag.String(
		"write-local",
		"",
		"if set, write bridge.json and exit.json into this directory and skip SSH (unless empty with dry-run)",
	)
	logLevel := flag.String(
		"log-level",
		"info",
		"ULTRA_RELAY_LOG_LEVEL on both nodes (debug, info, warning|warn, error, none); see ultra-relay -log-level",
	)
	reuseBridgeSpec := flag.Bool(
		"reuse-bridge-spec",
		false,
		"SSH to bridge first: reuse front inbound keys, tunnel UUID, splithttp path/host/tls from existing spec.json; keep ULTRA_RELAY_ADMIN_TOKEN from remote environment when possible",
	)
	skipGeoDownload := flag.Bool(
		"skip-geo-download",
		false,
		"do not download geoip.dat/geosite.dat on the bridge (air-gapped: place files under geo_assets_dir yourself)",
	)
	geoReleaseTag := flag.String(
		"geo-release-tag",
		"",
		"pin geo bundle release tag on the bridge (empty = latest via GitHub API)",
	)
	routingMode := flag.String(
		"routing-mode",
		"",
		"bridge split routing: blocklist (default) or ru_direct; empty keeps -reuse-bridge-spec remote or blocklist on fresh install",
	)
	geositeBlockTags := flag.String(
		"geosite-block-tags",
		"",
		"optional comma-separated geosite category names (no geosite: prefix) routed to blackhole on bridge",
	)
	// ── Connection tuning flags ───────────────────────────────────────────────
	disableDOH := flag.Bool(
		"disable-doh",
		false,
		"disable DNS over HTTPS in Xray on both nodes (default: DoH is enabled)",
	)
	noFragment := flag.Bool(
		"no-fragment",
		false,
		"disable TLS ClientHello fragmentation on bridge→exit outbound (default: enabled)",
	)
	antiCensorProfile := flag.String(
		"anti-censor-profile",
		"",
		`network tuning profile: fast, balanced, or stealth (empty = balanced defaults)`,
	)
	publicXHTTPPort := flag.Int(
		"public-xhttp-port",
		0,
		"optional extra public VLESS+REALITY+XHTTP port for fallback client profiles (0 = do not open)",
	)
	splithttpPadding := flag.String(
		"splithttp-padding",
		"",
		`random-padding byte range for each splithttp chunk, e.g. "0-100" (default "0-100"); "0" disables`,
	)
	splithttpMaxChunkKB := flag.Int(
		"splithttp-max-chunk-kb",
		0,
		"max bytes per splithttp POST in kilobytes (0 = Xray default ~1 MB; e.g. 64 reduces burst size)",
	)
	realityFPs := flag.String(
		"reality-fingerprints",
		"",
		`comma-separated TLS fingerprint pool to rotate per reload, e.g. "chrome,firefox,safari" (default: all mainstream browsers)`,
	)
	warpFlag := flag.Bool(
		"warp",
		false,
		"install Cloudflare WARP on exit node and route outbound traffic through it (changes exit IP to Cloudflare)",
	)
	warpPort := flag.Int(
		"warp-port",
		40000,
		"local SOCKS5 port for WARP proxy on exit node (default 40000)",
	)
	transportFlag := flag.String(
		"transport",
		"splithttp",
		`bridge→exit tunnel transport: "splithttp" (default, XHTTP stream-up H2) or "grpc" (deprecated in Xray 26)`,
	)
	vlessFlowFlag := flag.String(
		"vless-flow",
		config.DefaultVLESSFlow,
		`VLESS flow for public REALITY clients (default xtls-rprx-vision); use with -disable-vless-flow to opt out`,
	)
	disableVLESSFlow := flag.Bool(
		"disable-vless-flow",
		false,
		"omit flow on public REALITY inbound and client exports (legacy clients; Xray 26 warnings remain)",
	)
	exitOnly := flag.Bool(
		"exit-only",
		false,
		"deploy only an exit VPS (register exit in bridge Admin API first; requires -bridge, -exit, -tunnel-uuid)",
	)
	tunnelUUIDFlag := flag.String(
		"tunnel-uuid",
		"",
		"VLESS tunnel UUID for this exit (required with -exit-only; from POST /v1/exits deploy hints)",
	)
	botTelegramProxy := flag.Bool(
		"bot-telegram-proxy",
		false,
		"enable local SOCKS5 inbound on bridge for ultra-bot Telegram API via active exit",
	)
	flag.Parse()
	transportExplicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "transport" {
			transportExplicit = true
		}
	})

	tun := *tunnelPort
	if tun == 0 {
		tun = *vlessPort
	}
	if tun <= 0 || tun > 65535 {
		fmt.Fprintln(os.Stderr, "ultra-install: -tunnel-port must be 1..65535 or 0 to match -vless-port")
		os.Exit(1)
	}

	logLevelNorm := strings.TrimSpace(*logLevel)
	if _, _, err := loglevel.ParseRelayLogLevel(logLevelNorm); err != nil {
		fmt.Fprintln(os.Stderr, "ultra-install:", err)
		os.Exit(2)
	}

	if *exitOnly {
		runExitOnly(exitOnlyOpts{
			bridgeHost:      *bridgeHost,
			exitHost:        *exitHost,
			sshUser:         *sshUser,
			identity:        *identity,
			remoteDir:       *remoteDir,
			projectRoot:     *projectRoot,
			binaryPath:      *binaryPath,
			tunnelUUID:      *tunnelUUIDFlag,
			tunnelPort:      tun,
			logLevel:        logLevelNorm,
			generateExitTLS: *generateExitTLS,
			warp:            *warpFlag,
			warpPort:        *warpPort,
			disableDOH:      *disableDOH,
			transport:       exitOnlyTransportValue(*transportFlag, transportExplicit),
			splithttpHost:   *splithttpHostFlag,
			splithttpPath:   *splithttpPathFlag,
			dryRun:          *dryRun,
			writeLocal:      *writeLocal,
		})
		return
	}

	if *bridgeHost == "" || *exitHost == "" {
		flag.Usage()
		os.Exit(2)
	}
	pub := *publicHost
	if pub == "" {
		pub = *bridgeHost
	}
	presetStr := strings.TrimSpace(*preset)
	realityDestStr := strings.TrimSpace(*realityDest)
	realitySNIStr := strings.TrimSpace(*realitySNI)
	if presetStr == "" || presetStr == "plusgaming" {
		presetStr = "apijson"
	}
	if presetStr != "apijson" && presetStr != "steamlike" {
		fmt.Fprintln(os.Stderr, "ultra-install: unsupported -preset (use apijson, steamlike, or plusgaming=apijson):", presetStr)
		os.Exit(2)
	}
	routingModeStr := strings.TrimSpace(*routingMode)
	if routingModeStr != "" && routingModeStr != config.RoutingModeBlocklist && routingModeStr != config.RoutingModeRUDirect {
		fmt.Fprintln(os.Stderr, "ultra-install: -routing-mode must be blocklist or ru_direct")
		os.Exit(2)
	}

	if !*reuseBridgeSpec {
		if realityDestStr == "" {
			fmt.Fprintln(os.Stderr, "ultra-install: -reality-dest is required (host:port) unless -reuse-bridge-spec")
			os.Exit(2)
		}
		if _, _, err := net.SplitHostPort(realityDestStr); err != nil {
			fmt.Fprintln(os.Stderr, "ultra-install: -reality-dest must be host:port")
			os.Exit(2)
		}
		if realitySNIStr == "" {
			host, _, err := net.SplitHostPort(realityDestStr)
			if err != nil {
				host = realityDestStr
			}
			realitySNIStr = host
		}
	}

	strat, err := mimic.New(presetStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	exitDialAddr := strings.TrimSpace(*exitDial)
	if exitDialAddr == "" {
		exitDialAddr = *exitHost
	}
	exit2DialAddr := strings.TrimSpace(*exit2Dial)
	if exit2DialAddr == "" {
		exit2DialAddr = strings.TrimSpace(*exit2Host)
	}

	var (
		mimicHost     string
		splitPath     string
		tunnelUUID    string
		realitySpec   config.RealitySpec
		splitTLS      config.SplitHTTPTLSSpec
		tlsProv       config.TunnelTLSProvision
		adminToken    string
		reused        bool
		bridgeOverlay *config.Spec
	)

	if *reuseBridgeSpec {
		remoteSpec := path.Join(*remoteDir, "spec.json")
		// Use || true so the script always exits 0; empty output means spec doesn't exist yet.
		script := fmt.Sprintf(`test -r %q && cat %q || true`, remoteSpec, remoteSpec)
		out, err := install.RunSSHOutput(*sshUser, *bridgeHost, *identity, script)
		if err != nil {
			fmt.Fprintln(os.Stderr, "reuse-bridge-spec: SSH read failed:", err)
			os.Exit(1)
		}
		out = bytes.TrimSpace(out)
		if len(out) == 0 {
			// First install: no spec on bridge yet — fall through to generate fresh keys.
			fmt.Println("reuse-bridge-spec: no existing spec on bridge — generating fresh keys.")
			*reuseBridgeSpec = false
		}
	}
	if *reuseBridgeSpec {
		remoteSpec := path.Join(*remoteDir, "spec.json")
		out, _ := install.RunSSHOutput(*sshUser, *bridgeHost, *identity,
			fmt.Sprintf(`cat %q`, remoteSpec))
		out = bytes.TrimSpace(out)
		var existing config.Spec
		if err := json.Unmarshal(out, &existing); err != nil {
			fmt.Fprintln(os.Stderr, "reuse-bridge-spec: parse spec:", err)
			os.Exit(1)
		}
		if existing.Role != config.RoleBridge {
			fmt.Fprintln(os.Stderr, "reuse-bridge-spec: remote spec role is not bridge")
			os.Exit(1)
		}
		if existing.Reality.PrivateKey == "" || existing.Reality.PublicKey == "" {
			fmt.Fprintln(os.Stderr, "reuse-bridge-spec: remote spec missing front inbound key material")
			os.Exit(1)
		}
		mp := strings.TrimSpace(existing.MimicPreset)
		if mp != "" {
			strat, err = mimic.New(mp)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		realitySpec = existing.Reality
		tunnelUUID = strings.TrimSpace(existing.Exit.TunnelUUID)
		if tunnelUUID == "" {
			tid := uuid.New()
			tunnelUUID = (&tid).String()
		}
		mimicHost = strings.TrimSpace(existing.SplithttpHost)
		if mimicHost == "" {
			mimicHost = strat.Host()
		}
		splitPath = strings.TrimSpace(existing.SplithttpPath)
		if splitPath == "" {
			splitPath = strat.NextPath()
		}
		splitTLS = existing.SplitHTTPTLS
		if splitTLS.ServerName == "" {
			splitTLS.ServerName = mimicHost
		}
		if len(splitTLS.Alpn) == 0 {
			splitTLS.Alpn = []string{"h2"}
		}
		if splitTLS.Fingerprint == "" {
			splitTLS.Fingerprint = "chrome"
		}
		if sh := strings.TrimSpace(*splithttpHostFlag); sh != "" {
			mimicHost = sh
			splitTLS.ServerName = mimicHost
		}
		if sp := strings.TrimSpace(*splithttpPathFlag); sp != "" {
			splitPath = sp
		}
		if existing.TunnelTLSProvision != "" {
			tlsProv = existing.TunnelTLSProvision
		} else if *generateExitTLS {
			tlsProv = config.TunnelTLSSelfSigned
		} else {
			tlsProv = config.TunnelTLSUserProv
		}
		envPath := path.Join(*remoteDir, "environment")
		envScript := fmt.Sprintf(`grep -E '^ULTRA_RELAY_ADMIN_TOKEN=' %q 2>/dev/null | head -1 || true`, envPath)
		if envOut, err := install.RunSSHOutput(*sshUser, *bridgeHost, *identity, envScript); err == nil {
			line := strings.TrimSpace(string(bytes.TrimSpace(envOut)))
			if strings.HasPrefix(line, "ULTRA_RELAY_ADMIN_TOKEN=") {
				adminToken = strings.TrimSpace(strings.TrimPrefix(line, "ULTRA_RELAY_ADMIN_TOKEN="))
			}
		}
		if adminToken == "" {
			adminTok := make([]byte, 32)
			if _, err := rand.Read(adminTok); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			adminToken = hex.EncodeToString(adminTok)
			fmt.Fprintln(os.Stderr, "reuse-bridge-spec: warning: could not read remote admin token; generated a new one")
		}
		snap := existing
		bridgeOverlay = &snap
		reused = true
	} else {
		rk, err := realitykey.Generate()
		if err != nil {
			fmt.Fprintln(os.Stderr, "reality keys:", err)
			os.Exit(1)
		}
		tunnelID := uuid.New()
		tunnelUUID = (&tunnelID).String()
		mimicHost = strat.Host()
		splitPath = strat.NextPath()
		if sh := strings.TrimSpace(*splithttpHostFlag); sh != "" {
			mimicHost = sh
		}
		if sp := strings.TrimSpace(*splithttpPathFlag); sp != "" {
			splitPath = sp
		}
		realitySpec = config.RealitySpec{
			Dest:        realityDestStr,
			ServerNames: realityServerNames(realityDestStr, realitySNIStr),
			PrivateKey:  rk.PrivateKey,
			ShortIDs:    []string{""},
			PublicKey:   rk.PublicKey,
			// Fingerprint intentionally left empty so bridgeInboundStream rotates
			// randomly from the pool on each Xray config build (anti-fingerprinting).
			SpiderX: "/",
		}
		splitTLS = config.SplitHTTPTLSSpec{
			ServerName:  mimicHost,
			Alpn:        []string{"h2"},
			Fingerprint: "chrome",
		}
		tlsProv = config.TunnelTLSUserProv
		if *generateExitTLS {
			tlsProv = config.TunnelTLSSelfSigned
		}
		adminTok := make([]byte, 32)
		if _, err := rand.Read(adminTok); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		adminToken = hex.EncodeToString(adminTok)
	}

	genExitTLS := *generateExitTLS

	var priorBootstrap []exits.BootstrapEntry
	if *reuseBridgeSpec {
		priorBootstrap = loadRemoteBootstrapEntries(*sshUser, *bridgeHost, *identity, *remoteDir)
	}

	var tunnelUUID2 string
	if strings.TrimSpace(*exit2Host) != "" {
		if strings.TrimSpace(*exit2Host) == strings.TrimSpace(*exitHost) {
			fmt.Fprintln(os.Stderr, "ultra-install: -exit2 must differ from -exit")
			os.Exit(2)
		}
		exit2Host := strings.TrimSpace(*exit2Host)
		tunnelUUID2 = resolveExitTunnelUUID(priorBootstrap, *sshUser, exit2Host, *identity, *remoteDir, exit2DialAddr, tun)
		if tunnelUUID2 == "" && install.SSHReachable(*sshUser, exit2Host, *identity) {
			tid2 := uuid.New()
			tunnelUUID2 = (&tid2).String()
		}
	}

	bridgeSpec := &config.Spec{
		SchemaVersion:      config.CurrentSpecSchemaVersion,
		Role:               config.RoleBridge,
		MimicPreset:        strat.Name(),
		SplithttpHost:      mimicHost,
		TunnelTLSProvision: tlsProv,
		ListenAddress:      "0.0.0.0",
		VLESSPort:          *vlessPort,
		AdminListen:        "127.0.0.1:8443",
		PublicHost:         pub,
		DevMode:            false,
		Reality:            realitySpec,
		Exit: config.ExitTunnelSpec{
			Address:    exitDialAddr,
			Port:       tun,
			TunnelUUID: tunnelUUID,
		},
		SplithttpPath: splitPath,
		SplitHTTPTLS:  splitTLS,
	}

	// ── Connection tuning defaults (always set; flags may override) ──────────
	bridgeSpec.AntiCensor = buildAntiCensorSpec(antiCensorTuning{
		Profile:                *antiCensorProfile,
		PublicXHTTPPort:        *publicXHTTPPort,
		DisableDOH:             *disableDOH,
		DisableFragment:        *noFragment,
		SplitHTTPPadding:       *splithttpPadding,
		SplitHTTPMaxChunkKB:    *splithttpMaxChunkKB,
		RealityFingerprintsCSV: *realityFPs,
	})

	bridgeSpec.GeoAssetsDir = path.Join(*remoteDir, "geo")
	bridgeSpec.GeositeExitTags = []string{"ru-blocked-all"}
	if bridgeOverlay != nil {
		if g := strings.TrimSpace(bridgeOverlay.GeoAssetsDir); g != "" {
			bridgeSpec.GeoAssetsDir = g
		}
		if len(bridgeOverlay.GeositeExitTags) > 0 {
			bridgeSpec.GeositeExitTags = append([]string(nil), bridgeOverlay.GeositeExitTags...)
		}
		if len(bridgeOverlay.GeoipExitTags) > 0 {
			bridgeSpec.GeoipExitTags = append([]string(nil), bridgeOverlay.GeoipExitTags...)
		}
		if len(bridgeOverlay.DomainDirect) > 0 {
			bridgeSpec.DomainDirect = append([]string(nil), bridgeOverlay.DomainDirect...)
		}
		if len(bridgeOverlay.DomainExit) > 0 {
			bridgeSpec.DomainExit = append([]string(nil), bridgeOverlay.DomainExit...)
		}
		if rm := strings.TrimSpace(bridgeOverlay.RoutingMode); rm != "" {
			bridgeSpec.RoutingMode = rm
		}
		if bridgeOverlay.SplitRouting != nil {
			v := *bridgeOverlay.SplitRouting
			bridgeSpec.SplitRouting = &v
		}
		if bridgeOverlay.XrayWire != nil {
			cpy := *bridgeOverlay.XrayWire
			if len(bridgeOverlay.XrayWire.SniffingDestOverride) > 0 {
				cpy.SniffingDestOverride = append([]string(nil), bridgeOverlay.XrayWire.SniffingDestOverride...)
			}
			bridgeSpec.XrayWire = &cpy
		}
		if bridgeOverlay.SOCKS5 != nil {
			cpy := *bridgeOverlay.SOCKS5
			if bridgeOverlay.SOCKS5.UDP != nil {
				u := *bridgeOverlay.SOCKS5.UDP
				cpy.UDP = &u
			}
			bridgeSpec.SOCKS5 = &cpy
		}
		if bridgeOverlay.BotTelegramProxy != nil {
			cpy := *bridgeOverlay.BotTelegramProxy
			bridgeSpec.BotTelegramProxy = &cpy
		}
		if len(bridgeOverlay.GeositeBlockTags) > 0 {
			bridgeSpec.GeositeBlockTags = append([]string(nil), bridgeOverlay.GeositeBlockTags...)
		}
		if bridgeOverlay.GeositeDirectTags != nil {
			bridgeSpec.GeositeDirectTags = append([]string(nil), bridgeOverlay.GeositeDirectTags...)
		}
		if bridgeOverlay.GeoipDirectTags != nil {
			bridgeSpec.GeoipDirectTags = append([]string(nil), bridgeOverlay.GeoipDirectTags...)
		}
		if bridgeOverlay.RuDirectTLDRegex != nil {
			v := *bridgeOverlay.RuDirectTLDRegex
			bridgeSpec.RuDirectTLDRegex = &v
		}
	}
	if routingModeStr != "" {
		bridgeSpec.RoutingMode = routingModeStr
	}
	if s := strings.TrimSpace(*geositeBlockTags); s != "" {
		bridgeSpec.GeositeBlockTags = splitCommaNonEmpty(s)
	}
	if *botTelegramProxy {
		if bridgeSpec.BotTelegramProxy == nil {
			bridgeSpec.BotTelegramProxy = &config.BotTelegramProxySpec{Enabled: true}
		} else {
			bridgeSpec.BotTelegramProxy.Enabled = true
		}
	}

	exitAntiCensor := buildAntiCensorSpec(antiCensorTuning{
		Profile:             *antiCensorProfile,
		DisableDOH:          *disableDOH,
		SplitHTTPPadding:    *splithttpPadding,
		SplitHTTPMaxChunkKB: *splithttpMaxChunkKB,
		WARPProxy:           *warpFlag,
		WARPProxyPort:       *warpPort,
	})

	var tunnelTransport config.TunnelTransport
	switch strings.TrimSpace(*transportFlag) {
	case "", "splithttp":
		bridgeSpec.TunnelTransport = config.TunnelTransportSplitHTTP
		tunnelTransport = config.TunnelTransportSplitHTTP
	case "grpc":
		fmt.Fprintln(os.Stderr, "WARNING: gRPC transport deprecated in Xray 26; use -transport splithttp (XHTTP stream-up H2)")
		bridgeSpec.TunnelTransport = config.TunnelTransportGRPC
		tunnelTransport = config.TunnelTransportGRPC
	default:
		fmt.Fprintf(os.Stderr, "ultra-install: unsupported -transport %q (use splithttp or grpc)\n", *transportFlag)
		os.Exit(2)
	}

	if *disableVLESSFlow {
		bridgeSpec.VLESSFlow = "none"
	} else if f := strings.TrimSpace(*vlessFlowFlag); f != "" {
		bridgeSpec.VLESSFlow = f
	} else {
		bridgeSpec.VLESSFlow = config.DefaultVLESSFlow
	}

	exitJSON, err := buildExitSpecJSON(
		*remoteDir, tun, tunnelUUID, strat.Name(), mimicHost, splitPath, splitTLS, tlsProv, tunnelTransport, exitAntiCensor,
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "exit spec:", err)
		os.Exit(1)
	}
	var exit2JSON []byte
	if tunnelUUID2 != "" {
		exit2JSON, err = buildExitSpecJSON(
			*remoteDir, tun, tunnelUUID2, strat.Name(), mimicHost, splitPath, splitTLS, tlsProv, tunnelTransport, exitAntiCensor,
		)
		if err != nil {
			fmt.Fprintln(os.Stderr, "exit2 spec:", err)
			os.Exit(1)
		}
	}

	if err := bridgeSpec.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "bridge spec:", err)
		os.Exit(1)
	}

	bridgeJSON, err := json.MarshalIndent(bridgeSpec, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	exitPlans := []exitDeployPlan{{
		Label:      "primary",
		SSHHost:    *exitHost,
		DialAddr:   exitDialAddr,
		Port:       tun,
		Name:       "primary",
		Priority:   100,
		TunnelUUID: tunnelUUID,
		SpecJSON:   exitJSON,
	}}
	if tunnelUUID2 != "" {
		name2 := strings.TrimSpace(*exit2Name)
		if name2 == "" {
			name2 = "backup"
		}
		pri2 := *exit2Priority
		if pri2 <= 0 {
			pri2 = 200
		}
		exitPlans = append(exitPlans, exitDeployPlan{
			Label:      "backup",
			SSHHost:    strings.TrimSpace(*exit2Host),
			DialAddr:   exit2DialAddr,
			Port:       tun,
			Name:       name2,
			Priority:   pri2,
			TunnelUUID: tunnelUUID2,
			SpecJSON:   exit2JSON,
		})
	}
	previewOutcomes := previewExitOutcomes(exitPlans, *sshUser, *identity)
	bootstrapEntries := buildBootstrapEntries(exitPlans, priorBootstrap, previewOutcomes)
	bootstrapJSON, err := json.MarshalIndent(bootstrapEntries, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// ── PostgreSQL configuration (if requested) ─────────────────────────────
	var installWarn installWarnings
	var pgCfg *install.PostgresConfig
	var dbDSN string
	if *dbHost != "" || (*dbHost == "" && *dbReplica != "") {
		dbSSH := *dbSSHUser
		if dbSSH == "" {
			dbSSH = *sshUser
		}
		primaryHost := *dbHost
		if primaryHost == "" {
			primaryHost = *bridgeHost
		}
		replicaHost := *dbReplica
		if replicaHost == "" && *dbReplica == "" {
			replicaHost = *exitHost
		}

		// When the DB is co-located with the bridge the relay connects via loopback.
		// For pg_hba we use 127.0.0.1 in that case; otherwise the bridge's external IP.
		bridgeIPForHBA := *bridgeHost
		if primaryHost == *bridgeHost {
			bridgeIPForHBA = "127.0.0.1"
		}

		pc := &install.PostgresConfig{
			DBName:      *dbName,
			DBUser:      *dbUser,
			BridgeHost:  bridgeIPForHBA,
			ReplicaHost: replicaHost,
		}
		if err := pc.Defaults(); err != nil {
			fmt.Fprintln(os.Stderr, "postgres config:", err)
			os.Exit(1)
		}
		pgCfg = pc

		// Relay connects to DB on loopback when co-located; external IP otherwise.
		dsnHost := primaryHost
		if primaryHost == *bridgeHost {
			dsnHost = "127.0.0.1"
		}
		dbDSN = pc.DSN(dsnHost)
		bridgeSpec.Database = &config.DatabaseSpec{DSN: dbDSN}
		bridgeSpec.Stats = &config.StatsSpec{CollectIntervalSeconds: 60}

		// Re-marshal bridge spec with DB fields added.
		bridgeJSON, err = json.MarshalIndent(bridgeSpec, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		if !*dryRun {
			// Configure locale and timezone on DB hosts before installing PostgreSQL,
			// so package scripts run without "perl: Setting locale failed" warnings.
			fmt.Printf("Configuring system locale/timezone on %s …\n", primaryHost)
			if err := install.SetupSystem(dbSSH, primaryHost, *identity); err != nil {
				fmt.Fprintln(os.Stderr, "system setup (primary):", err)
				os.Exit(1)
			}
			replicaReachable := replicaHost != "" && replicaHost != primaryHost
			if replicaReachable && !install.SSHReachable(dbSSH, replicaHost, *identity) {
				installWarn.add("PostgreSQL replica (%s): SSH недоступен — пропуск", replicaHost)
				replicaReachable = false
			}
			if replicaReachable {
				fmt.Printf("Configuring system locale/timezone on %s …\n", replicaHost)
				if err := install.SetupSystem(dbSSH, replicaHost, *identity); err != nil {
					installWarn.add("PostgreSQL replica (%s): SSH недоступен — %v", replicaHost, err)
					replicaReachable = false
				}
			}
			fmt.Printf("Setting up PostgreSQL primary on %s …\n", primaryHost)
			if err := install.SetupPrimaryPostgres(dbSSH, primaryHost, *identity, *pc); err != nil {
				fmt.Fprintln(os.Stderr, "postgres primary setup:", err)
				os.Exit(1)
			}
			fmt.Println("PostgreSQL primary ready.")

			if replicaReachable {
				fmt.Printf("Setting up PostgreSQL replica on %s …\n", replicaHost)
				if err := install.SetupReplicaPostgres(dbSSH, replicaHost, *identity, *pc, primaryHost); err != nil {
					installWarn.add("PostgreSQL replica (%s): установка не выполнена — %v", replicaHost, err)
				} else {
					fmt.Println("PostgreSQL replica ready.")
				}
			}
		}
	}

	if *dryRun {
		if reused {
			fmt.Println("=== reuse-bridge-spec: loaded front keys, tunnel, splithttp from remote bridge ===")
		}
		fmt.Println("=== bridge spec ===")
		fmt.Println(string(bridgeJSON))
		fmt.Println("=== exit spec (primary) ===")
		fmt.Println(string(exitJSON))
		if len(exit2JSON) > 0 {
			fmt.Println("=== exit spec (exit2) ===")
			fmt.Println(string(exit2JSON))
		}
		fmt.Println("=== exit_nodes.bootstrap.json ===")
		fmt.Println(string(bootstrapJSON))
		if *warpFlag {
			fmt.Printf("=== WARP: would install on exit, proxy port %d ===\n", *warpPort)
		}
		fmt.Println("=== one-time values (store securely) ===")
		fmt.Println("admin_token:", adminToken)
		fmt.Println("tunnel_uuid:", tunnelUUID)
		if tunnelUUID2 != "" {
			fmt.Println("tunnel_uuid2:", tunnelUUID2)
		}
		fmt.Println("splithttp_path:", splitPath)
		if dbDSN != "" {
			fmt.Println("db_dsn:", dbDSN)
			if pgCfg != nil {
				fmt.Println("db_repl_password:", pgCfg.ReplPassword)
			}
		}
		return
	}

	if *writeLocal != "" {
		if err := os.MkdirAll(*writeLocal, 0o700); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := os.WriteFile(filepath.Join(*writeLocal, "bridge-spec.json"), bridgeJSON, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := os.WriteFile(filepath.Join(*writeLocal, "exit-spec.json"), exitJSON, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if len(exit2JSON) > 0 {
			if err := os.WriteFile(filepath.Join(*writeLocal, "exit2-spec.json"), exit2JSON, 0o600); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		if err := os.WriteFile(filepath.Join(*writeLocal, exits.BootstrapFileName), bootstrapJSON, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("Wrote", filepath.Join(*writeLocal, "bridge-spec.json"))
		fmt.Println("Wrote", filepath.Join(*writeLocal, "exit-spec.json"))
		if len(exit2JSON) > 0 {
			fmt.Println("Wrote", filepath.Join(*writeLocal, "exit2-spec.json"))
		}
		fmt.Println("Wrote", filepath.Join(*writeLocal, exits.BootstrapFileName))
		return
	}

	systemdLocal := filepath.Join(*projectRoot, "deploy/systemd/ultra-relay.service")
	if _, err := os.Stat(systemdLocal); err != nil {
		fmt.Fprintln(os.Stderr, "systemd unit not found:", systemdLocal)
		os.Exit(1)
	}
	if _, err := os.Stat(*binaryPath); err != nil {
		fmt.Fprintln(os.Stderr, "binary not found:", *binaryPath)
		os.Exit(1)
	}

	fmt.Printf("Configuring system locale/timezone on bridge %s …\n", *bridgeHost)
	if err := install.SetupSystem(*sshUser, *bridgeHost, *identity); err != nil {
		fmt.Fprintln(os.Stderr, "system setup (bridge):", err)
		os.Exit(1)
	}

	bridgePrep := fmt.Sprintf(
		`set -euo pipefail; REMOTE_DIR=%q; mkdir -p "$REMOTE_DIR" && chmod 700 "$REMOTE_DIR"; id -u ultra-relay >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin ultra-relay`,
		*remoteDir,
	)
	if err := install.RunSSH(*sshUser, *bridgeHost, *identity, bridgePrep); err != nil {
		fmt.Fprintln(os.Stderr, "bridge prepare:", err)
		os.Exit(1)
	}
	if !*skipGeoDownload && bridgeSpec.SplitRoutingEnabled() {
		fmt.Println("bridge: installing runetfreedom geo →", bridgeSpec.GeoAssetsDir)
		geoScript := install.RunetfreedomGeoRemoteScript(bridgeSpec.GeoAssetsDir, *geoReleaseTag)
		if err := install.RunSSH(*sshUser, *bridgeHost, *identity, geoScript); err != nil {
			fmt.Fprintln(os.Stderr, "bridge geo download:", err)
			os.Exit(1)
		}
	}

	exitCommon := exitDeployCommon{
		sshUser:      *sshUser,
		identity:     *identity,
		remoteDir:    *remoteDir,
		binaryPath:   *binaryPath,
		systemdLocal: systemdLocal,
		logLevel:     logLevelNorm,
		mimicHost:    mimicHost,
		genExitTLS:   genExitTLS,
		warp:         *warpFlag,
		warpPort:     *warpPort,
	}
	deployOutcomes := make(map[string]exitDeployOutcome, len(exitPlans))
	for _, plan := range exitPlans {
		if !install.SSHReachable(exitCommon.sshUser, plan.SSHHost, exitCommon.identity) {
			installWarn.add("exit %s (%s): SSH недоступен — деплой пропущен", plan.Label, plan.SSHHost)
			deployOutcomes[plan.Label] = exitDeployOutcome{}
			continue
		}
		certPin, err := deployExitNode(exitCommon, plan)
		if err != nil {
			installWarn.add("exit %s (%s): деплой не выполнен — %v", plan.Label, plan.SSHHost, err)
			deployOutcomes[plan.Label] = exitDeployOutcome{}
			continue
		}
		deployOutcomes[plan.Label] = exitDeployOutcome{Deployed: true, CertPin: certPin}
		fmt.Printf("Exit node %s deployed: %s\n", plan.Label, plan.SSHHost)
	}
	if countDeployedOutcomes(deployOutcomes) == 0 {
		fmt.Fprintln(os.Stderr, "ultra-install: ни один exit не задеployed — установка прервана")
		os.Exit(1)
	}
	bootstrapEntries = buildBootstrapEntries(exitPlans, priorBootstrap, deployOutcomes)
	bootstrapJSON, err = json.MarshalIndent(bootstrapEntries, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	tmpBridge := filepath.Join(os.TempDir(), "ultra-bridge-spec.json")
	tmpBootstrap := filepath.Join(os.TempDir(), exits.BootstrapFileName)
	tmpEnv := filepath.Join(os.TempDir(), "ultra-relay.env")
	bridgeEnv := fmt.Sprintf("ULTRA_RELAY_ADMIN_TOKEN=%s\nULTRA_RELAY_LOG_LEVEL=%s\n", adminToken, logLevelNorm)
	if dbDSN != "" {
		bridgeEnv += install.FormatDBEnvLine(dbDSN)
	}
	if err := os.WriteFile(tmpBridge, bridgeJSON, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(tmpBootstrap, bootstrapJSON, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(tmpEnv, []byte(bridgeEnv), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer func() {
		_ = os.Remove(tmpBridge)
		_ = os.Remove(tmpBootstrap)
		_ = os.Remove(tmpEnv)
	}()

	for _, fn := range []func() error{
		func() error { return install.SCP(*identity, *binaryPath, *sshUser, *bridgeHost, "/tmp/ultra-relay") },
		func() error {
			return install.SCP(*identity, tmpBridge, *sshUser, *bridgeHost, path.Join(*remoteDir, "spec.json"))
		},
		func() error {
			return install.SCP(*identity, tmpBootstrap, *sshUser, *bridgeHost, path.Join(*remoteDir, exits.BootstrapFileName))
		},
		func() error {
			return install.SCP(*identity, tmpEnv, *sshUser, *bridgeHost, path.Join(*remoteDir, "environment.tmp"))
		},
	} {
		if err := fn(); err != nil {
			fmt.Fprintln(os.Stderr, "scp:", err)
			os.Exit(1)
		}
	}

	remoteFinalize := fmt.Sprintf(`set -euo pipefail
REMOTE_DIR=%q
install -m 755 /tmp/ultra-relay /usr/local/bin/ultra-relay
rm -f /tmp/ultra-relay
install -m 600 "$REMOTE_DIR/environment.tmp" /etc/ultra-relay/environment
rm -f "$REMOTE_DIR/environment.tmp"
chown -R ultra-relay:ultra-relay "$REMOTE_DIR"
chmod 700 "$REMOTE_DIR"
chmod 600 "$REMOTE_DIR/spec.json" || true
chmod 600 "$REMOTE_DIR/%s" || true
chmod 600 /etc/ultra-relay/environment
`, *remoteDir, exits.BootstrapFileName)

	if err := install.RunSSH(*sshUser, *bridgeHost, *identity, remoteFinalize); err != nil {
		fmt.Fprintln(os.Stderr, "bridge finalize:", err)
		os.Exit(1)
	}
	bridgePorts := []int{bridgeSpec.VLESSPort}
	if bridgeSpec.AntiCensor != nil && bridgeSpec.AntiCensor.PublicXHTTPPort > 0 {
		bridgePorts = append(bridgePorts, bridgeSpec.AntiCensor.PublicXHTTPPort)
	}
	if err := install.SetupFirewallPorts(*sshUser, *bridgeHost, *identity, bridgePorts); err != nil {
		fmt.Fprintln(os.Stderr, "bridge firewall:", err)
		os.Exit(1)
	}

	tmpUnit := filepath.Join(os.TempDir(), "ultra-relay.service")
	unitBytes, err := os.ReadFile(systemdLocal)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(tmpUnit, unitBytes, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer func() { _ = os.Remove(tmpUnit) }()

	if err := install.SCP(*identity, tmpUnit, *sshUser, *bridgeHost, "/tmp/ultra-relay.service"); err != nil {
		fmt.Fprintln(os.Stderr, "unit scp:", err)
		os.Exit(1)
	}
	unitMv := `mv /tmp/ultra-relay.service /etc/systemd/system/ultra-relay.service && systemctl daemon-reload && systemctl enable ultra-relay && systemctl restart ultra-relay`
	if err := install.RunSSH(*sshUser, *bridgeHost, *identity, unitMv); err != nil {
		fmt.Fprintln(os.Stderr, "systemctl:", err)
		os.Exit(1)
	}

	fmt.Println("Install finished.")
	fmt.Println("Exit nodes (bootstrap on bridge):", *exitHost)
	if tunnelUUID2 != "" {
		fmt.Println("  backup:", strings.TrimSpace(*exit2Host))
		fmt.Println("  bootstrap:", path.Join(*remoteDir, exits.BootstrapFileName))
	}
	installWarn.printSummary()
	if reused {
		fmt.Println("Preserved front inbound keys, tunnel UUID, and splithttp settings from existing bridge spec (-reuse-bridge-spec).")
	}
	fmt.Println("Log level (ULTRA_RELAY_LOG_LEVEL on both nodes):", logLevelNorm)
	fmt.Println("Admin token (save securely):", adminToken)
	fmt.Println("SSH port-forward example: ssh -L 8443:127.0.0.1:8443", fmt.Sprintf("%s@%s", *sshUser, *bridgeHost))
	fmt.Println("See deploy/TLS.md for tunnel TLS posture (tunnel_tls_provision:", tlsProv, ").")
	if *warpFlag {
		fmt.Printf("Cloudflare WARP proxy: exit outbound traffic routed through 127.0.0.1:%d → Cloudflare IP.\n", *warpPort)
		fmt.Println("  Destination sites see a Cloudflare IP instead of the VPS datacenter IP.")
		fmt.Println("  On reboot, WARP reconnects automatically via warp-svc (systemd).")
	}
	if dbDSN != "" {
		fmt.Println("PostgreSQL DSN (save securely):", dbDSN)
		if pgCfg != nil && pgCfg.ReplicaHost != "" {
			fmt.Println("PostgreSQL replication user:", pgCfg.ReplUser)
			fmt.Println("PostgreSQL replica host:", pgCfg.ReplicaHost)
		}
		fmt.Println("Traffic stats API: GET /v1/traffic/monthly  GET /v1/users/{uuid}/traffic")
	}
}
