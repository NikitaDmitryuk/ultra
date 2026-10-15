// Command ultra-install builds paired bridge/exit specs and can install them over SSH (key auth only).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
	"github.com/NikitaDmitryuk/ultra/internal/loglevel"
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

func normalizeDomainMatchers(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, ":") {
			out = append(out, item)
		} else {
			out = append(out, "domain:"+item)
		}
	}
	return out
}

func appendUniqueStrings(base []string, add ...string) []string {
	seen := make(map[string]bool, len(base)+len(add))
	out := append([]string(nil), base...)
	for _, v := range base {
		seen[v] = true
	}
	for _, v := range add {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func main() {
	if handlePlanSubcommand(os.Args[1:]) {
		return
	}
	legacyMain()
}

func legacyMain() {
	bridgeHost := flag.String("bridge", "", "bridge VPS hostname or IP (SSH target)")
	exitHost := flag.String("exit", "", "exit VPS hostname or IP (SSH target)")

	// PostgreSQL flags
	dbHost := flag.String("db-host", "", "dedicated PostgreSQL server IP (required for database provisioning)")
	dbSSHIdentity := flag.String("database-ssh-key", "", "SSH private key path for dedicated DB server (default: same as -identity)")
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
	identity := flag.String("bridge-ssh-key", "", "bridge operator SSH key path")
	exitIdentity := flag.String("main-exit-ssh-key", "", "main exit operator SSH key path")
	publicHost := flag.String("public-host", "", "hostname or IP clients use to reach the bridge (default: -bridge)")
	splithttpHostFlag := flag.String(
		"splithttp-host",
		"",
		"override spec splithttp_host and tunnel TLS server name / cert CN (required for a custom hostname)",
	)
	splithttpPathFlag := flag.String(
		"splithttp-path",
		"",
		"override spec splithttp_path (default: /ultra-xhttp)",
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
	domainDirect := flag.String(
		"domain-direct",
		"",
		"optional comma-separated Xray domain matchers forced to direct on bridge (plain names become domain:name)",
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
			identity:        *exitIdentity,
			bridgeIdentity:  *identity,
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

	values := map[string]string{
		"BRIDGE_IP": *bridgeHost, "MAIN_EXIT_IP": *exitHost, "EXIT_DIAL": *exitDial, "EXIT2": *exit2Host, "EXIT2_DIAL": *exit2Dial, "EXIT2_NAME": *exit2Name, "EXIT2_PRIORITY": strconv.Itoa(*exit2Priority),
		"SSH_USER": *sshUser, "BRIDGE_SSH_KEY": *identity, "MAIN_EXIT_SSH_KEY": *exitIdentity, "PUBLIC_HOST": *publicHost, "REMOTE_DIR": *remoteDir, "RELAY_BINARY": *binaryPath, "PROJECT_ROOT": *projectRoot,
		"PRESET": "standard", "REALITY_DEST": *realityDest, "REALITY_SNI": *realitySNI, "VLESS_PORT": strconv.Itoa(*vlessPort), "TUNNEL_PORT": strconv.Itoa(tun),
		"REUSE_BRIDGE_SPEC": strconv.FormatBool(*reuseBridgeSpec), "GENERATE_EXIT_TLS": strconv.FormatBool(*generateExitTLS), "LOG_LEVEL": logLevelNorm,
		"DATABASE_IP": *dbHost, "DATABASE_SSH_KEY": *dbSSHIdentity, "DB_NAME": *dbName, "DB_USER": *dbUser,
		"SPLITHTTP_HOST": *splithttpHostFlag, "SPLITHTTP_PATH": *splithttpPathFlag, "SKIP_GEO_DOWNLOAD": strconv.FormatBool(*skipGeoDownload), "GEO_RELEASE_TAG": *geoReleaseTag,
		"ROUTING_MODE": *routingMode, "GEOSITE_BLOCK_TAGS": *geositeBlockTags, "DOMAIN_DIRECT": *domainDirect,
		"DOH_DISABLE": strconv.FormatBool(*disableDOH), "FRAGMENT_DISABLE": strconv.FormatBool(*noFragment), "ANTI_CENSOR_PROFILE": *antiCensorProfile,
		"PUBLIC_XHTTP_PORT": strconv.Itoa(*publicXHTTPPort), "SPLITHTTP_PADDING": *splithttpPadding, "SPLITHTTP_MAX_CHUNK_KB": strconv.Itoa(*splithttpMaxChunkKB), "REALITY_FINGERPRINTS": *realityFPs,
		"WARP_ENABLE": strconv.FormatBool(*warpFlag), "WARP_PORT": strconv.Itoa(*warpPort), "TRANSPORT": *transportFlag, "VLESS_FLOW": *vlessFlowFlag, "DISABLE_VLESS_FLOW": strconv.FormatBool(*disableVLESSFlow),
	}
	plan := installplan.LegacyValuesToPlan(values)
	plan.Artifacts.RelayBinary = *binaryPath
	plan.Artifacts.ProjectRoot = *projectRoot
	plan.Features.BotTelegramProxy = *botTelegramProxy
	exitOnErr("legacy flag plan", installplan.ValidatePlan(plan))
	if *dryRun || *writeLocal != "" {
		if plan.Bridge.ReuseSpec {
			fmt.Fprintln(os.Stderr, "reuse requires read-only target inspection; use apply --config or render a fresh plan")
			os.Exit(2)
		}
		desired, err := installplan.RenderDesiredState(plan)
		exitOnErr("render legacy flags", err)
		if *writeLocal != "" {
			exitOnErr("private render directory", os.MkdirAll(*writeLocal, 0700))
			exitOnErr("render bridge", os.WriteFile(filepath.Join(*writeLocal, "bridge.json"), desired.BridgeSpec, 0600))
			for name, data := range desired.ExitSpecs {
				filename := "exit-" + sanitizeName(name) + ".json"
				if name == "primary" {
					filename = "exit.json"
				}
				exitOnErr("render exit", os.WriteFile(filepath.Join(*writeLocal, filename), data, 0600))
			}
		} else {
			fmt.Println("plan valid; secrets are available only through --write-local private artifacts")
		}
		return
	}
	applyPlanN(plan, "human")
}
