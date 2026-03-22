// Command ultra-install builds paired bridge/exit specs and can install them over SSH (key auth only).
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/xtls/xray-core/common/uuid"

	"github.com/NikitaDmitryuk/ultra/config"
	"github.com/NikitaDmitryuk/ultra/internal/install"
	"github.com/NikitaDmitryuk/ultra/internal/loglevel"
	"github.com/NikitaDmitryuk/ultra/internal/realitykey"
	"github.com/NikitaDmitryuk/ultra/mimic"
)

func main() {
	bridgeHost := flag.String("bridge", "", "bridge VPS hostname or IP (SSH target)")
	exitHost := flag.String("exit", "", "exit VPS hostname or IP (SSH target)")
	sshUser := flag.String("ssh-user", "root", "SSH user (key auth; avoid password automation)")
	identity := flag.String("identity", "", "path to SSH private key (optional if ssh uses agent)")
	publicHost := flag.String("public-host", "", "hostname or IP clients use to reach the bridge (default: -bridge)")
	preset := flag.String("preset", "plusgaming", "HTTP profile between nodes (only plusgaming is supported in this release)")
	realityDest := flag.String("reality-dest", "plusgaming.yandex.ru:443", "outer TLS peer host:port on the bridge")
	realitySNI := flag.String("reality-sni", "plusgaming.yandex.ru", "outer TLS server name (SNI) on the bridge")
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
	if presetStr != "" && presetStr != "plusgaming" {
		fmt.Fprintln(os.Stderr, "ultra-install: unsupported -preset (only plusgaming in this release):", presetStr)
		os.Exit(2)
	}
	presetStr = "plusgaming"

	logLevelNorm := strings.TrimSpace(*logLevel)
	if _, _, err := loglevel.ParseRelayLogLevel(logLevelNorm); err != nil {
		fmt.Fprintln(os.Stderr, "ultra-install:", err)
		os.Exit(2)
	}

	strat, err := mimic.New(presetStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	mimicHost := strat.Host()
	splitPath := strat.NextPath()

	rk, err := realitykey.Generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, "reality keys:", err)
		os.Exit(1)
	}
	tunnelID := uuid.New()
	tunnelUUID := (&tunnelID).String()

	adminTok := make([]byte, 32)
	if _, err := rand.Read(adminTok); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	adminToken := hex.EncodeToString(adminTok)

	tlsProv := config.TunnelTLSUserProv
	if *generateExitTLS {
		tlsProv = config.TunnelTLSSelfSigned
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
		Reality: config.RealitySpec{
			Dest:        realityDestStr,
			ServerNames: []string{realitySNIStr},
			PrivateKey:  rk.PrivateKey,
			ShortIDs:    []string{""},
			PublicKey:   rk.PublicKey,
			Fingerprint: "chrome",
			SpiderX:     "/",
		},
		Exit: config.ExitTunnelSpec{
			Address:    *exitHost,
			Port:       tun,
			TunnelUUID: tunnelUUID,
		},
		SplithttpPath: splitPath,
		SplitHTTPTLS: config.SplitHTTPTLSSpec{
			ServerName:  mimicHost,
			Alpn:        []string{"h2"},
			Fingerprint: "chrome",
		},
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
		SplitHTTPTLS: config.SplitHTTPTLSSpec{
			ServerName:  mimicHost,
			Alpn:        []string{"h2"},
			Fingerprint: "chrome",
		},
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
	exitPrep := fmt.Sprintf(
		`set -euo pipefail; REMOTE_DIR=%q; mkdir -p "$REMOTE_DIR" && chmod 700 "$REMOTE_DIR"; id -u ultra-relay >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin ultra-relay`,
		*remoteDir,
	)
	if err := install.RunSSH(*sshUser, *exitHost, *identity, exitPrep); err != nil {
		fmt.Fprintln(os.Stderr, "exit prepare:", err)
		os.Exit(1)
	}

	if *generateExitTLS {
		ssl := fmt.Sprintf(
			`set -euo pipefail; REMOTE_DIR=%q; CN=%q; openssl req -x509 -newkey rsa:2048 -keyout "$REMOTE_DIR/privkey.pem" -out "$REMOTE_DIR/fullchain.pem" -days 3650 -nodes -subj "/CN=$CN"; chown ultra-relay:ultra-relay "$REMOTE_DIR/privkey.pem" "$REMOTE_DIR/fullchain.pem"; chmod 600 "$REMOTE_DIR/privkey.pem" "$REMOTE_DIR/fullchain.pem"`,
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
	fmt.Println("Log level (ULTRA_RELAY_LOG_LEVEL on both nodes):", logLevelNorm)
	fmt.Println("Admin token (save securely):", adminToken)
	fmt.Println("SSH port-forward example: ssh -L 8443:127.0.0.1:8443", fmt.Sprintf("%s@%s", *sshUser, *bridgeHost))
	fmt.Println("See deploy/TLS.md for tunnel TLS posture (tunnel_tls_provision:", tlsProv, ").")
}
