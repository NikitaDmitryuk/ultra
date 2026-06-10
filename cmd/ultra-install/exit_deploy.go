package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/install"
)

type exitDeployPlan struct {
	Label      string
	SSHHost    string
	DialAddr   string
	Port       int
	Name       string
	Priority   int
	TunnelUUID string
	SpecJSON   []byte
}

type exitDeployOutcome struct {
	Deployed bool
	CertPin  string
}

func mergePriorBootstrapEntry(entry *exits.BootstrapEntry, prior []exits.BootstrapEntry) {
	if entry == nil || len(prior) == 0 {
		return
	}
	for _, p := range prior {
		if strings.TrimSpace(p.Address) == strings.TrimSpace(entry.Address) && p.Port == entry.Port {
			if strings.TrimSpace(entry.PinnedPeerCertSHA256) == "" && strings.TrimSpace(p.PinnedPeerCertSHA256) != "" {
				entry.PinnedPeerCertSHA256 = p.PinnedPeerCertSHA256
			}
			if strings.TrimSpace(entry.TunnelUUID) == "" && strings.TrimSpace(p.TunnelUUID) != "" {
				entry.TunnelUUID = p.TunnelUUID
			}
			return
		}
	}
}

func buildBootstrapEntries(
	plans []exitDeployPlan,
	prior []exits.BootstrapEntry,
	outcomes map[string]exitDeployOutcome,
) []exits.BootstrapEntry {
	out := make([]exits.BootstrapEntry, 0, len(plans))
	for _, plan := range plans {
		entry := exits.BootstrapEntry{
			Name:       plan.Name,
			Address:    plan.DialAddr,
			Port:       plan.Port,
			TunnelUUID: plan.TunnelUUID,
			Priority:   plan.Priority,
		}
		mergePriorBootstrapEntry(&entry, prior)
		o := outcomes[plan.Label]
		if o.Deployed {
			entry.Enabled = exits.BootstrapEnabledPtr(true)
			if o.CertPin != "" {
				entry.PinnedPeerCertSHA256 = o.CertPin
			}
		} else {
			entry.Enabled = exits.BootstrapEnabledPtr(false)
		}
		out = append(out, entry)
	}
	return out
}

func previewExitOutcomes(plans []exitDeployPlan, sshUser, identity string) map[string]exitDeployOutcome {
	out := make(map[string]exitDeployOutcome, len(plans))
	for _, plan := range plans {
		out[plan.Label] = exitDeployOutcome{
			Deployed: install.SSHReachable(sshUser, plan.SSHHost, identity),
		}
	}
	return out
}

func countDeployedOutcomes(outcomes map[string]exitDeployOutcome) int {
	n := 0
	for _, o := range outcomes {
		if o.Deployed {
			n++
		}
	}
	return n
}

type exitDeployCommon struct {
	sshUser      string
	identity     string
	remoteDir    string
	binaryPath   string
	systemdLocal string
	logLevel     string
	mimicHost    string
	genExitTLS   bool
	warp         bool
	warpPort     int
}

func buildExitSpecJSON(
	remoteDir string,
	tun int,
	tunnelUUID string,
	stratName string,
	mimicHost string,
	splitPath string,
	splitTLS config.SplitHTTPTLSSpec,
	tlsProv config.TunnelTLSProvision,
	transport config.TunnelTransport,
	exitAnti *config.AntiCensorSpec,
) ([]byte, error) {
	exitSpec := &config.Spec{
		SchemaVersion:      config.CurrentSpecSchemaVersion,
		Role:               config.RoleExit,
		MimicPreset:        stratName,
		SplithttpHost:      mimicHost,
		TunnelTLSProvision: tlsProv,
		ListenAddress:      "0.0.0.0",
		VLESSPort:          tun,
		Exit: config.ExitTunnelSpec{
			TunnelUUID: tunnelUUID,
		},
		SplithttpPath: splitPath,
		SplitHTTPTLS:  splitTLS,
		ExitCertPaths: config.CertPaths{
			CertFile: path.Join(remoteDir, "fullchain.pem"),
			KeyFile:  path.Join(remoteDir, "privkey.pem"),
		},
		AntiCensor: exitAnti,
	}
	if transport != "" {
		exitSpec.TunnelTransport = transport
	}
	if err := exitSpec.Validate(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(exitSpec, "", "  ")
}

func deployExitNode(c exitDeployCommon, plan exitDeployPlan) (string, error) {
	host := plan.SSHHost
	fmt.Printf("Configuring system locale/timezone on exit %s …\n", host)
	if err := install.SetupSystem(c.sshUser, host, c.identity); err != nil {
		return "", fmt.Errorf("system setup (%s): %w", host, err)
	}
	exitPrep := fmt.Sprintf(
		`set -euo pipefail; REMOTE_DIR=%q; mkdir -p "$REMOTE_DIR" && chmod 700 "$REMOTE_DIR"; id -u ultra-relay >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin ultra-relay`,
		c.remoteDir,
	)
	if err := install.RunSSH(c.sshUser, host, c.identity, exitPrep); err != nil {
		return "", fmt.Errorf("exit prepare (%s): %w", host, err)
	}
	if c.warp {
		fmt.Printf("exit %s: installing Cloudflare WARP (proxy mode → 127.0.0.1:%d) …\n", host, c.warpPort)
		if err := install.SetupWARP(c.sshUser, host, c.identity, c.warpPort); err != nil {
			return "", fmt.Errorf("warp setup (%s): %w", host, err)
		}
		if err := install.SetupWARPWatchdog(c.sshUser, host, c.identity, c.warpPort); err != nil {
			return "", fmt.Errorf("warp watchdog (%s): %w", host, err)
		}
	}
	if c.genExitTLS {
		ssl := fmt.Sprintf(
			`set -euo pipefail
REMOTE_DIR=%q
CN=%q
if [[ -f "$REMOTE_DIR/fullchain.pem" && -f "$REMOTE_DIR/privkey.pem" ]]; then
  echo "ultra: exit TLS cert already present — skip generation"
  exit 0
fi
openssl req -x509 -newkey rsa:2048 -keyout "$REMOTE_DIR/privkey.pem" -out "$REMOTE_DIR/fullchain.pem" -days 3650 -nodes -subj "/CN=$CN" -addext "subjectAltName=DNS:$CN"
chown ultra-relay:ultra-relay "$REMOTE_DIR/privkey.pem" "$REMOTE_DIR/fullchain.pem"
chmod 600 "$REMOTE_DIR/privkey.pem" "$REMOTE_DIR/fullchain.pem"`,
			c.remoteDir,
			c.mimicHost,
		)
		if err := install.RunSSH(c.sshUser, host, c.identity, ssl); err != nil {
			return "", fmt.Errorf("exit tls (%s): %w", host, err)
		}
	} else {
		check := fmt.Sprintf(
			`test -f %q/fullchain.pem && test -f %q/privkey.pem`,
			c.remoteDir, c.remoteDir,
		)
		if err := install.RunSSH(c.sshUser, host, c.identity, check); err != nil {
			return "", fmt.Errorf("exit tls (%s): fullchain.pem/privkey.pem missing (use -generate-exit-tls or place certs manually)", host)
		}
	}

	tmpExit := filepath.Join(os.TempDir(), fmt.Sprintf("ultra-exit-spec-%s.json", host))
	tmpEnvExit := filepath.Join(os.TempDir(), fmt.Sprintf("ultra-relay-exit-%s.env", host))
	exitEnv := fmt.Sprintf("ULTRA_RELAY_LOG_LEVEL=%s\n", c.logLevel)
	if err := os.WriteFile(tmpExit, plan.SpecJSON, 0o600); err != nil {
		return "", err
	}
	if err := os.WriteFile(tmpEnvExit, []byte(exitEnv), 0o600); err != nil {
		return "", err
	}
	defer func() {
		_ = os.Remove(tmpExit)
		_ = os.Remove(tmpEnvExit)
	}()

	for _, fn := range []func() error{
		func() error { return install.SCP(c.identity, c.binaryPath, c.sshUser, host, "/tmp/ultra-relay") },
		func() error {
			return install.SCP(c.identity, tmpExit, c.sshUser, host, path.Join(c.remoteDir, "spec.json"))
		},
		func() error {
			return install.SCP(c.identity, tmpEnvExit, c.sshUser, host, path.Join(c.remoteDir, "environment.tmp"))
		},
	} {
		if err := fn(); err != nil {
			return "", fmt.Errorf("scp (%s): %w", host, err)
		}
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
`, c.remoteDir)
	if err := install.RunSSH(c.sshUser, host, c.identity, exitFinalize); err != nil {
		return "", fmt.Errorf("exit finalize (%s): %w", host, err)
	}
	if err := install.SetupFirewallPorts(c.sshUser, host, c.identity, []int{plan.Port}); err != nil {
		return "", fmt.Errorf("exit firewall (%s): %w", host, err)
	}

	tmpUnit := filepath.Join(os.TempDir(), "ultra-relay.service")
	unitBytes, err := os.ReadFile(c.systemdLocal)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(tmpUnit, unitBytes, 0o644); err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(tmpUnit) }()

	if err := install.SCP(c.identity, tmpUnit, c.sshUser, host, "/tmp/ultra-relay.service"); err != nil {
		return "", fmt.Errorf("unit scp (%s): %w", host, err)
	}
	unitMv := `mv /tmp/ultra-relay.service /etc/systemd/system/ultra-relay.service && systemctl daemon-reload && systemctl enable ultra-relay && systemctl restart ultra-relay`
	if err := install.RunSSH(c.sshUser, host, c.identity, unitMv); err != nil {
		return "", fmt.Errorf("systemctl (%s): %w", host, err)
	}
	certPin, err := install.RemoteCertSHA256(c.sshUser, host, c.identity, path.Join(c.remoteDir, "fullchain.pem"))
	if err != nil {
		return "", fmt.Errorf("exit cert pin (%s): %w", host, err)
	}
	return certPin, nil
}
