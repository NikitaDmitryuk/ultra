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
	"github.com/NikitaDmitryuk/ultra/internal/install"
	"github.com/NikitaDmitryuk/ultra/internal/loglevel"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/NikitaDmitryuk/ultra/internal/realitykey"
)

// realityServerNames builds inbound server_names for REALITY; sni defaults to the host part of dest.
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
	exitDial := flag.String(
		"exit-dial",
		"",
		"hostname or IP for bridge→exit splithttp dial in spec (default: same as -exit); use DNS name when dial by IP breaks Host validation",
	)
	sshUser := flag.String("ssh-user", "root", "SSH user (key auth; avoid password automation)")
	identity := flag.String("identity", "", "path to SSH private key (optional if ssh uses agent)")
	publicHost := flag.String("public-host", "", "hostname or IP clients use to reach the bridge (default: -bridge)")
	preset := flag.String("preset", "apijson", "HTTP profile between nodes (apijson; plusgaming is an alias)")
	realityDest := flag.String("reality-dest", "", "REALITY TLS mirror target host:port (required unless -reuse-bridge-spec)")
	realitySNI := flag.String("reality-sni", "", "SNI for REALITY inbound (default: host from -reality-dest)")
	vlessPort := flag.Int("vless-port", 443, "TCP port: public VLESS+REALITY listener on the bridge (clients connect here)")
	tunnelPort := flag.Int(
		"tunnel-port",
		0,
		"TCP port on exit for bridge→exit splithttp; 0 means same as -vless-port (legacy single-port setup)",
	)
	remoteDir := flag.String("remote-dir", "/etc/ultra-relay", "remote config directory")
	projectRoot := flag.String("project-root", ".", "repo root (for systemd unit and users.json.sample)")
	binaryPath := flag.String("binary", "ultra-relay-linux-amd64", "local ultra-relay binary to upload")
	usersSample := flag.String("users-sample", "", "path to users.json seed (default: <project-root>/users.json.sample)")
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
		"SSH to bridge first: reuse REALITY keys, tunnel UUID, splithttp path/host/tls from existing spec.json; keep ULTRA_RELAY_ADMIN_TOKEN from remote environment when possible",
	)
	skipGeoDownload := flag.Bool(
		"skip-geo-download",
		false,
		"do not download runetfreedom geoip.dat/geosite.dat on the bridge (for air-gapped installs; you must place files under geo_assets_dir yourself)",
	)
	geoReleaseTag := flag.String(
		"geo-release-tag",
		"",
		"pin runetfreedom/russia-v2ray-rules-dat release tag on the bridge (empty = latest via GitHub API)",
	)
	flag.Parse()

	tun := *tunnelPort
	if tun == 0 {
		tun = *vlessPort
	}
	if tun <= 0 || tun > 65535 {
		fmt.Fprintln(os.Stderr, "ultra-install: -tunnel-port must be 1..65535 or 0 to match -vless-port")
		os.Exit(1)
	}

	if *bridgeHost == "" || *exitHost == "" {
		flag.Usage()
		os.Exit(2)
	}
	pub := *publicHost
	if pub == "" {
		pub = *bridgeHost
	}
	usersPath := *usersSample
	if usersPath == "" {
		usersPath = filepath.Join(*projectRoot, "users.json.sample")
	}

	presetStr := strings.TrimSpace(*preset)
	realityDestStr := strings.TrimSpace(*realityDest)
	realitySNIStr := strings.TrimSpace(*realitySNI)
	if presetStr != "" && presetStr != "plusgaming" && presetStr != "apijson" {
		fmt.Fprintln(os.Stderr, "ultra-install: unsupported -preset (only apijson in this release; plusgaming is an alias):", presetStr)
		os.Exit(2)
	}
	if presetStr == "" || presetStr == "plusgaming" {
		presetStr = "apijson"
	}

	logLevelNorm := strings.TrimSpace(*logLevel)
	if _, _, err := loglevel.ParseRelayLogLevel(logLevelNorm); err != nil {
		fmt.Fprintln(os.Stderr, "ultra-install:", err)
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
		script := fmt.Sprintf(`set -euo pipefail; test -r %q && cat %q`, remoteSpec, remoteSpec)
		out, err := install.RunSSHOutput(*sshUser, *bridgeHost, *identity, script)
		if err != nil {
			fmt.Fprintln(os.Stderr, "reuse-bridge-spec: read remote spec:", err)
			os.Exit(1)
		}
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
			fmt.Fprintln(os.Stderr, "reuse-bridge-spec: remote spec missing reality keys")
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
		realitySpec = config.RealitySpec{
			Dest:        realityDestStr,
			ServerNames: realityServerNames(realityDestStr, realitySNIStr),
			PrivateKey:  rk.PrivateKey,
			ShortIDs:    []string{""},
			PublicKey:   rk.PublicKey,
			Fingerprint: "chrome",
			SpiderX:     "/",
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
	if reused && tlsProv == config.TunnelTLSSelfSigned {
		genExitTLS = false
	}

	bridgeSpec := &config.Spec{
		SchemaVersion:      config.CurrentSpecSchemaVersion,
		Role:               config.RoleBridge,
		MimicPreset:        strat.Name(),
		SplithttpHost:      mimicHost,
		TunnelTLSProvision: tlsProv,
		UsersPath:          path.Join(*remoteDir, "users.json"),
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
	}

	exitSpec := &config.Spec{
		SchemaVersion:      config.CurrentSpecSchemaVersion,
		Role:               config.RoleExit,
		MimicPreset:        strat.Name(),
		SplithttpHost:      mimicHost,
		TunnelTLSProvision: tlsProv,
		UsersPath:          "",
		ListenAddress:      "0.0.0.0",
		VLESSPort:          tun,
		PublicHost:         "",
		DevMode:            false,
		Reality:            config.RealitySpec{},
		Exit: config.ExitTunnelSpec{
			Address:    "",
			Port:       0,
			TunnelUUID: tunnelUUID,
		},
		SplithttpPath: splitPath,
		SplitHTTPTLS:  splitTLS,
		ExitCertPaths: config.CertPaths{
			CertFile: path.Join(*remoteDir, "fullchain.pem"),
			KeyFile:  path.Join(*remoteDir, "privkey.pem"),
		},
	}

	if err := bridgeSpec.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "bridge spec:", err)
		os.Exit(1)
	}
	if err := exitSpec.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "exit spec:", err)
		os.Exit(1)
	}

	bridgeJSON, err := json.MarshalIndent(bridgeSpec, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	exitJSON, err := json.MarshalIndent(exitSpec, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if *dryRun {
		if reused {
			fmt.Println("=== reuse-bridge-spec: loaded REALITY/tunnel/splithttp from remote bridge ===")
		}
		fmt.Println("=== bridge spec ===")
		fmt.Println(string(bridgeJSON))
		fmt.Println("=== exit spec ===")
		fmt.Println(string(exitJSON))
		fmt.Println("=== one-time values (store securely) ===")
		fmt.Println("admin_token:", adminToken)
		fmt.Println("tunnel_uuid:", tunnelUUID)
		fmt.Println("splithttp_path:", splitPath)
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
		fmt.Println("Wrote", filepath.Join(*writeLocal, "bridge-spec.json"))
		fmt.Println("Wrote", filepath.Join(*writeLocal, "exit-spec.json"))
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
	if _, err := os.Stat(usersPath); err != nil {
		fmt.Fprintln(os.Stderr, "users sample not found:", usersPath)
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
	exitPrep := fmt.Sprintf(
		`set -euo pipefail; REMOTE_DIR=%q; mkdir -p "$REMOTE_DIR" && chmod 700 "$REMOTE_DIR"; id -u ultra-relay >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin ultra-relay`,
		*remoteDir,
	)
	if err := install.RunSSH(*sshUser, *exitHost, *identity, exitPrep); err != nil {
		fmt.Fprintln(os.Stderr, "exit prepare:", err)
		os.Exit(1)
	}

	if genExitTLS {
		// SAN required: Go 1.23+ x509 rejects hostname verify when cert has only legacy CN (bridge splithttp client).
		ssl := fmt.Sprintf(
			`set -euo pipefail; REMOTE_DIR=%q; CN=%q; openssl req -x509 -newkey rsa:2048 -keyout "$REMOTE_DIR/privkey.pem" -out "$REMOTE_DIR/fullchain.pem" -days 3650 -nodes -subj "/CN=$CN" -addext "subjectAltName=DNS:$CN"; chown ultra-relay:ultra-relay "$REMOTE_DIR/privkey.pem" "$REMOTE_DIR/fullchain.pem"; chmod 600 "$REMOTE_DIR/privkey.pem" "$REMOTE_DIR/fullchain.pem"`,
			*remoteDir,
			mimicHost,
		)
		if err := install.RunSSH(*sshUser, *exitHost, *identity, ssl); err != nil {
			fmt.Fprintln(os.Stderr, "exit tls:", err)
			os.Exit(1)
		}
	}

	tmpBridge := filepath.Join(os.TempDir(), "ultra-bridge-spec.json")
	tmpExit := filepath.Join(os.TempDir(), "ultra-exit-spec.json")
	tmpEnv := filepath.Join(os.TempDir(), "ultra-relay.env")
	tmpEnvExit := filepath.Join(os.TempDir(), "ultra-relay-exit.env")
	bridgeEnv := fmt.Sprintf("ULTRA_RELAY_ADMIN_TOKEN=%s\nULTRA_RELAY_LOG_LEVEL=%s\n", adminToken, logLevelNorm)
	exitEnv := fmt.Sprintf("ULTRA_RELAY_LOG_LEVEL=%s\n", logLevelNorm)
	_ = os.WriteFile(tmpBridge, bridgeJSON, 0o600)
	_ = os.WriteFile(tmpExit, exitJSON, 0o600)
	_ = os.WriteFile(tmpEnv, []byte(bridgeEnv), 0o600)
	_ = os.WriteFile(tmpEnvExit, []byte(exitEnv), 0o600)
	defer func() {
		_ = os.Remove(tmpBridge)
		_ = os.Remove(tmpExit)
		_ = os.Remove(tmpEnv)
		_ = os.Remove(tmpEnvExit)
	}()

	for _, fn := range []func() error{
		func() error { return install.SCP(*identity, *binaryPath, *sshUser, *bridgeHost, "/tmp/ultra-relay") },
		func() error { return install.SCP(*identity, *binaryPath, *sshUser, *exitHost, "/tmp/ultra-relay") },
		func() error {
			return install.SCP(*identity, tmpBridge, *sshUser, *bridgeHost, path.Join(*remoteDir, "spec.json"))
		},
		func() error {
			return install.SCP(*identity, tmpExit, *sshUser, *exitHost, path.Join(*remoteDir, "spec.json"))
		},
		func() error {
			return install.SCP(*identity, tmpEnv, *sshUser, *bridgeHost, path.Join(*remoteDir, "environment.tmp"))
		},
		func() error {
			return install.SCP(*identity, tmpEnvExit, *sshUser, *exitHost, path.Join(*remoteDir, "environment.tmp"))
		},
	} {
		if err := fn(); err != nil {
			fmt.Fprintln(os.Stderr, "scp:", err)
			os.Exit(1)
		}
	}

	usersRemote := path.Join(*remoteDir, "users.json")
	checkUsers := fmt.Sprintf(`test -f %q`, usersRemote)
	if err := install.RunSSH(*sshUser, *bridgeHost, *identity, checkUsers); err != nil {
		if err := install.SCP(*identity, usersPath, *sshUser, *bridgeHost, usersRemote); err != nil {
			fmt.Fprintln(os.Stderr, "users scp:", err)
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
chmod 600 "$REMOTE_DIR/users.json" 2>/dev/null || true
chmod 600 /etc/ultra-relay/environment
`, *remoteDir)

	if err := install.RunSSH(*sshUser, *bridgeHost, *identity, remoteFinalize); err != nil {
		fmt.Fprintln(os.Stderr, "bridge finalize:", err)
		os.Exit(1)
	}

	exitFinalize := fmt.Sprintf(`set -euo pipefail
REMOTE_DIR=%q
install -m 755 /tmp/ultra-relay /usr/local/bin/ultra-relay
rm -f /tmp/ultra-relay
install -m 600 "$REMOTE_DIR/environment.tmp" /etc/ultra-relay/environment
rm -f "$REMOTE_DIR/environment.tmp"
chmod 600 /etc/ultra-relay/environment
chown -R ultra-relay:ultra-relay "$REMOTE_DIR"
chmod 700 "$REMOTE_DIR"
chmod 600 "$REMOTE_DIR/spec.json" || true
`, *remoteDir)
	if err := install.RunSSH(*sshUser, *exitHost, *identity, exitFinalize); err != nil {
		fmt.Fprintln(os.Stderr, "exit finalize:", err)
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

	for _, h := range []string{*bridgeHost, *exitHost} {
		if err := install.SCP(*identity, tmpUnit, *sshUser, h, "/tmp/ultra-relay.service"); err != nil {
			fmt.Fprintln(os.Stderr, "unit scp:", err)
			os.Exit(1)
		}
		unitMv := `mv /tmp/ultra-relay.service /etc/systemd/system/ultra-relay.service && systemctl daemon-reload && systemctl enable ultra-relay && systemctl restart ultra-relay`
		if err := install.RunSSH(*sshUser, h, *identity, unitMv); err != nil {
			fmt.Fprintln(os.Stderr, "systemctl:", err)
			os.Exit(1)
		}
	}

	fmt.Println("Install finished.")
	if reused {
		fmt.Println("Preserved REALITY keys, tunnel UUID, and splithttp settings from existing bridge spec (-reuse-bridge-spec).")
	}
	fmt.Println("Log level (ULTRA_RELAY_LOG_LEVEL on both nodes):", logLevelNorm)
	fmt.Println("Admin token (save securely):", adminToken)
	fmt.Println("SSH port-forward example: ssh -L 8443:127.0.0.1:8443", fmt.Sprintf("%s@%s", *sshUser, *bridgeHost))
	fmt.Println("See deploy/TLS.md for tunnel TLS posture (tunnel_tls_provision:", tlsProv, ").")
}
