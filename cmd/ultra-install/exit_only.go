package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
)

type exitOnlyOpts struct {
	bridgeHost      string
	exitHost        string
	sshUser         string
	identity        string
	bridgeIdentity  string
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

func exitOnlyTransportValue(value string, explicit bool) string {
	if !explicit {
		return ""
	}
	return strings.TrimSpace(value)
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

	if o.remoteDir != "/etc/ultra-relay" {
		exitOnErr("exit-only", fmt.Errorf("canonical remote directory required"))
	}
	ctx := context.Background()
	root := os.Getenv("ULTRA_INSTALL_STATE_DIR")
	if root == "" {
		cache, err := os.UserCacheDir()
		exitOnErr("exit-only state", err)
		root = filepath.Join(cache, "ultra-install")
	}
	root, err := filepath.Abs(root)
	exitOnErr("exit-only state", err)
	exitOnErr("exit-only private state", ensurePrivateBootstrapDirectory(root))
	ctx, release, err := deployansible.WithOperationLock(ctx, root)
	exitOnErr("exit-only lease", err)
	defer release()
	requestJSON, err := json.Marshal(map[string]any{"bridge": o.bridgeHost, "exit": o.exitHost, "uuid": o.tunnelUUID, "port": o.tunnelPort, "identity": o.identity, "binary": o.binaryPath, "log": o.logLevel, "warp": o.warp, "warp_port": o.warpPort, "transport": o.transport, "host": o.splithttpHost, "path": o.splithttpPath, "disable_doh": o.disableDOH})
	exitOnErr("exit-only identity", err)
	// The route identity differentiates jobs; pure option fields are private below.
	digest := sha256.Sum256(append(requestJSON, []byte(o.bridgeHost+"|"+o.exitHost+"|"+o.tunnelUUID)...))
	attemptRoot := filepath.Join(root, "exit-"+hex.EncodeToString(digest[:]))
	exitOnErr("exit-only private journal", ensurePrivateBootstrapDirectory(attemptRoot))
	directory, err := beginBootstrapAttempt(attemptRoot)
	exitOnErr("exit-only attempt", err)
	exitOnErr("exit-only private attempt", ensurePrivateBootstrapDirectory(directory))
	bridgeIdentity := o.bridgeIdentity
	if bridgeIdentity == "" {
		bridgeIdentity = o.identity
	}
	plan := &installplan.InstallPlan{SSH: installplan.SSHConfig{User: o.sshUser, Identity: bridgeIdentity}, Bridge: installplan.BridgeConfig{SSHHost: o.bridgeHost, RemoteDir: o.remoteDir}}
	executable := os.Getenv("ULTRA_ANSIBLE_EXECUTABLE")
	if executable == "" {
		executable = "/opt/ultra-ansible/current/venv/bin/ansible-playbook"
	}
	_, inspection, err := inspectBootstrap(ctx, plan, directory, "/usr/bin/python3", executable, root)
	exitOnErr("exit-only bridge inspection", err)
	out, err := inspection["bridge"].file("spec.json")
	exitOnErr("exit-only bridge specification", err)
	var bridge config.Spec
	exitOnErr("exit-only bridge specification", json.Unmarshal(out, &bridge))
	if bridge.Role != config.RoleBridge {
		exitOnErr("exit-only", fmt.Errorf("remote target is not a bridge"))
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
	switch t := strings.TrimSpace(o.transport); t {
	case "":
		if bridge.TunnelTransport != "" {
			exitSpec.TunnelTransport = bridge.TunnelTransport
		} else {
			exitSpec.TunnelTransport = config.TunnelTransportSplitHTTP
		}
	case "grpc":
		fmt.Fprintln(os.Stderr, "WARNING: gRPC transport deprecated in Xray 26; use -transport splithttp (XHTTP stream-up H2)")
		exitSpec.TunnelTransport = config.TunnelTransportGRPC
	case "splithttp":
		exitSpec.TunnelTransport = config.TunnelTransportSplitHTTP
	default:
		fmt.Fprintln(os.Stderr, `exit-only: -transport must be "splithttp" or "grpc"`)
		os.Exit(2)
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

	identity, err := filepath.Abs(o.identity)
	exitOnErr("exit-only SSH identity", err)
	pins := os.Getenv("ULTRA_INSTALL_SSH_KNOWN_HOSTS")
	if pins == "" {
		pins = filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts")
	}
	pins, err = filepath.Abs(pins)
	exitOnErr("exit-only pins", err)
	bridgeIP, err := net.ResolveIPAddr("ip4", o.bridgeHost)
	exitOnErr("exit-only bridge IPv4", err)
	source, err := filepath.Abs(o.binaryPath)
	exitOnErr("exit-only binary", err)
	sum, err := sourceSHA(source)
	exitOnErr("exit-only binary", err)
	request := deployansible.ExitRequest{Host: o.exitHost, User: o.sshUser, Identity: identity, KnownHosts: pins, BridgeIPv4: bridgeIP.IP.String(), Spec: *exitSpec}
	exitOnErr("exit-only inputs", request.Validate())
	inventory := map[string]any{"all": map[string]any{"children": map[string]any{"exits": map[string]any{"hosts": map[string]any{"exit": map[string]any{"ansible_host": o.exitHost, "ansible_user": o.sshUser, "ansible_ssh_private_key_file": identity, "ansible_ssh_args": "-F /dev/null -C -o ControlMaster=no -o ControlPath=none", "ansible_ssh_common_args": "-o StrictHostKeyChecking=yes -o UpdateHostKeys=no -o IdentitiesOnly=yes -o UserKnownHostsFile=" + shellQuote(pins)}}}}}}
	variables := map[string]any{"ultra_lock_directory": root, "ultra_spec": exitSpec, "ultra_bridge_ipv4": bridgeIP.IP.String(), "ultra_relay_source": source, "ultra_relay_sha256": sum, "ultra_relay_environment": "ULTRA_RELAY_LOG_LEVEL=" + o.logLevel + "\n", "ultra_warp_enabled": o.warp, "ultra_warp_port": o.warpPort}
	_, err = deployansible.RunLocal(ctx, "configure-exit-operator", inventory, variables, filepath.Join(directory, "apply"), "/usr/bin/python3", executable)
	exitOnErr("Ansible exit-only", err)
	exitOnErr("exit-only completion", completeBootstrapAttempt(attemptRoot, directory))
	fmt.Println("Exit node installed:", o.exitHost)
}
