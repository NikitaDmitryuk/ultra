package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/install"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
)

type exitOnlyOpts struct {
	bridgeHost      string
	exitHost        string
	sshUser         string
	identity        string
	remoteDir       string
	projectRoot     string
	binaryPath      string
	tunnelUUID      string
	tunnelPort      int
	logLevel        string
	generateExitTLS bool
	warp            bool
	warpPort        int
	disableDOH      bool
	transport       string
	splithttpHost   string
	splithttpPath   string
	dryRun          bool
	writeLocal      string
}

func runExitOnly(o exitOnlyOpts) {
	if o.exitHost == "" || strings.TrimSpace(o.tunnelUUID) == "" {
		fmt.Fprintln(os.Stderr, "ultra-install: -exit-only requires -exit and -tunnel-uuid")
		os.Exit(2)
	}
	if o.bridgeHost == "" {
		fmt.Fprintln(os.Stderr, "ultra-install: -exit-only requires -bridge to read shared tunnel settings")
		os.Exit(2)
	}

	remoteSpec := path.Join(o.remoteDir, "spec.json")
	out, err := install.RunSSHOutput(o.sshUser, o.bridgeHost, o.identity,
		fmt.Sprintf(`cat %q`, remoteSpec))
	if err != nil {
		fmt.Fprintln(os.Stderr, "exit-only: read bridge spec:", err)
		os.Exit(1)
	}
	out = bytes.TrimSpace(out)
	var bridge config.Spec
	if err := json.Unmarshal(out, &bridge); err != nil {
		fmt.Fprintln(os.Stderr, "exit-only: parse bridge spec:", err)
		os.Exit(1)
	}
	if bridge.Role != config.RoleBridge {
		fmt.Fprintln(os.Stderr, "exit-only: remote spec is not bridge role")
		os.Exit(1)
	}

	preset := strings.TrimSpace(bridge.MimicPreset)
	if preset == "" {
		preset = "apijson"
	}
	strat, err := mimic.New(preset)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	mimicHost := strings.TrimSpace(bridge.SplithttpHost)
	if mimicHost == "" {
		mimicHost = strat.Host()
	}
	splitPath := strings.TrimSpace(bridge.SplithttpPath)
	if splitPath == "" {
		splitPath = strat.NextPath()
	}
	splitTLS := bridge.SplitHTTPTLS
	if splitTLS.ServerName == "" {
		splitTLS.ServerName = mimicHost
	}
	if len(splitTLS.Alpn) == 0 {
		splitTLS.Alpn = []string{"h2"}
	}
	if splitTLS.Fingerprint == "" {
		splitTLS.Fingerprint = "chrome"
	}
	if sh := strings.TrimSpace(o.splithttpHost); sh != "" {
		mimicHost = sh
		splitTLS.ServerName = mimicHost
	}
	if sp := strings.TrimSpace(o.splithttpPath); sp != "" {
		splitPath = sp
	}

	tun := o.tunnelPort
	if tun <= 0 {
		tun = bridge.Exit.Port
	}
	if tun <= 0 {
		tun = bridge.VLESSPort
	}
	if tun <= 0 {
		tun = 443
	}

	tlsProv := bridge.TunnelTLSProvision
	if tlsProv == "" {
		tlsProv = config.TunnelTLSSelfSigned
	}

	exitAntiCensor := tunnelSplitHTTPAntiCensorFromBridge(&bridge, antiCensorTuning{
		DisableDOH:    o.disableDOH,
		WARPProxy:     o.warp,
		WARPProxyPort: o.warpPort,
	})

	exitSpec := &config.Spec{
		SchemaVersion:      config.CurrentSpecSchemaVersion,
		Role:               config.RoleExit,
		MimicPreset:        strat.Name(),
		SplithttpHost:      mimicHost,
		TunnelTLSProvision: tlsProv,
		ListenAddress:      "0.0.0.0",
		VLESSPort:          tun,
		Exit: config.ExitTunnelSpec{
			TunnelUUID: strings.TrimSpace(o.tunnelUUID),
		},
		SplithttpPath: splitPath,
		SplitHTTPTLS:  splitTLS,
		ExitCertPaths: config.CertPaths{
			CertFile: path.Join(o.remoteDir, "fullchain.pem"),
			KeyFile:  path.Join(o.remoteDir, "privkey.pem"),
		},
		AntiCensor: exitAntiCensor,
	}
	if bridge.TunnelTransport != "" {
		exitSpec.TunnelTransport = bridge.TunnelTransport
	}
	if t := strings.TrimSpace(o.transport); t == "grpc" {
		fmt.Fprintln(os.Stderr, "WARNING: gRPC transport deprecated in Xray 26; use -transport splithttp (XHTTP stream-up H2)")
		exitSpec.TunnelTransport = config.TunnelTransportGRPC
	} else {
		exitSpec.TunnelTransport = config.TunnelTransportSplitHTTP
	}

	if err := exitSpec.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "exit spec:", err)
		os.Exit(1)
	}

	exitJSON, err := json.MarshalIndent(exitSpec, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if o.dryRun {
		fmt.Println("=== exit-only: exit spec ===")
		fmt.Println(string(exitJSON))
		fmt.Println("=== tunnel_uuid:", o.tunnelUUID, "===")
		return
	}

	if o.writeLocal != "" {
		if err := os.MkdirAll(o.writeLocal, 0o700); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		p := filepath.Join(o.writeLocal, "exit-spec.json")
		if err := os.WriteFile(p, exitJSON, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("Wrote", p)
		return
	}

	systemdLocal := filepath.Join(o.projectRoot, "deploy/systemd/ultra-relay.service")
	if _, err := os.Stat(systemdLocal); err != nil {
		fmt.Fprintln(os.Stderr, "systemd unit not found:", systemdLocal)
		os.Exit(1)
	}
	if _, err := os.Stat(o.binaryPath); err != nil {
		fmt.Fprintln(os.Stderr, "binary not found:", o.binaryPath)
		os.Exit(1)
	}

	fmt.Printf("Configuring system locale/timezone on exit %s …\n", o.exitHost)
	if err := install.SetupSystem(o.sshUser, o.exitHost, o.identity); err != nil {
		fmt.Fprintln(os.Stderr, "system setup (exit):", err)
		os.Exit(1)
	}

	exitPrep := fmt.Sprintf(
		`set -euo pipefail; REMOTE_DIR=%q; mkdir -p "$REMOTE_DIR" && chmod 700 "$REMOTE_DIR"; id -u ultra-relay >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin ultra-relay`,
		o.remoteDir,
	)
	if err := install.RunSSH(o.sshUser, o.exitHost, o.identity, exitPrep); err != nil {
		fmt.Fprintln(os.Stderr, "exit prepare:", err)
		os.Exit(1)
	}

	if o.warp {
		fmt.Printf("exit: installing Cloudflare WARP (proxy mode → 127.0.0.1:%d) …\n", o.warpPort)
		if err := install.SetupWARP(o.sshUser, o.exitHost, o.identity, o.warpPort); err != nil {
			fmt.Fprintln(os.Stderr, "warp setup:", err)
			os.Exit(1)
		}
		if err := install.SetupWARPWatchdog(o.sshUser, o.exitHost, o.identity, o.warpPort); err != nil {
			fmt.Fprintln(os.Stderr, "warp watchdog setup:", err)
			os.Exit(1)
		}
	}

	if o.generateExitTLS {
		ssl := fmt.Sprintf(
			`set -euo pipefail; REMOTE_DIR=%q; CN=%q; openssl req -x509 -newkey rsa:2048 -keyout "$REMOTE_DIR/privkey.pem" -out "$REMOTE_DIR/fullchain.pem" -days 3650 -nodes -subj "/CN=$CN" -addext "subjectAltName=DNS:$CN"; chown ultra-relay:ultra-relay "$REMOTE_DIR/privkey.pem" "$REMOTE_DIR/fullchain.pem"; chmod 600 "$REMOTE_DIR/privkey.pem" "$REMOTE_DIR/fullchain.pem"`,
			o.remoteDir,
			mimicHost,
		)
		if err := install.RunSSH(o.sshUser, o.exitHost, o.identity, ssl); err != nil {
			fmt.Fprintln(os.Stderr, "exit tls:", err)
			os.Exit(1)
		}
	}

	tmpExit := filepath.Join(os.TempDir(), "ultra-exit-spec.json")
	tmpEnvExit := filepath.Join(os.TempDir(), "ultra-relay-exit.env")
	exitEnv := fmt.Sprintf("ULTRA_RELAY_LOG_LEVEL=%s\n", o.logLevel)
	_ = os.WriteFile(tmpExit, exitJSON, 0o600)
	_ = os.WriteFile(tmpEnvExit, []byte(exitEnv), 0o600)
	defer func() {
		_ = os.Remove(tmpExit)
		_ = os.Remove(tmpEnvExit)
	}()

	for _, fn := range []func() error{
		func() error { return install.SCP(o.identity, o.binaryPath, o.sshUser, o.exitHost, "/tmp/ultra-relay") },
		func() error {
			return install.SCP(o.identity, tmpExit, o.sshUser, o.exitHost, path.Join(o.remoteDir, "spec.json"))
		},
		func() error {
			return install.SCP(o.identity, tmpEnvExit, o.sshUser, o.exitHost, path.Join(o.remoteDir, "environment.tmp"))
		},
		func() error {
			return install.SCP(o.identity, systemdLocal, o.sshUser, o.exitHost, "/etc/systemd/system/ultra-relay.service")
		},
	} {
		if err := fn(); err != nil {
			fmt.Fprintln(os.Stderr, "exit-only deploy:", err)
			os.Exit(1)
		}
	}

	finish := fmt.Sprintf(
		`set -euo pipefail; REMOTE_DIR=%q; install -o ultra-relay -g ultra-relay -m 755 /tmp/ultra-relay /usr/local/bin/ultra-relay; install -o ultra-relay -g ultra-relay -m 600 "$REMOTE_DIR/environment.tmp" "$REMOTE_DIR/environment"; systemctl daemon-reload; systemctl enable ultra-relay; systemctl restart ultra-relay`,
		o.remoteDir,
	)
	if err := install.RunSSH(o.sshUser, o.exitHost, o.identity, finish); err != nil {
		fmt.Fprintln(os.Stderr, "exit-only finish:", err)
		os.Exit(1)
	}
	fmt.Println("Exit node installed:", o.exitHost)
}
