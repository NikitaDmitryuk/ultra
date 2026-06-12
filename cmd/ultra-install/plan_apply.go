package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/install"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func applyPlanN(p *installplan.InstallPlan, format string) {
	renderOpts := installplan.RenderOptions{}
	if p.Bridge.ReuseSpec {
		emitInstallEvent(format, installplan.EventStep, "", "loading existing bridge state for reuse", "bridge")
		existing, err := loadPlanRemoteBridgeSpec(p)
		if err != nil {
			emitInstallEvent(
				format,
				installplan.EventWarning,
				"",
				fmt.Sprintf("existing bridge spec not available, generating fresh state: %v", err),
				"bridge",
			)
			p.Bridge.ReuseSpec = false
		} else {
			renderOpts.ExistingBridge = existing
			renderOpts.ExistingAdminToken = loadPlanRemoteAdminToken(p)
			renderOpts.PriorBootstrap = loadRemoteBootstrapEntries(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, p.Bridge.RemoteDir)
			if len(renderOpts.PriorBootstrap) == 0 && existing.Exit.Address != "" && existing.Exit.Port > 0 && existing.Exit.TunnelUUID != "" {
				renderOpts.PriorBootstrap = append(renderOpts.PriorBootstrap, exits.BootstrapEntry{
					Name:       "primary",
					Address:    existing.Exit.Address,
					Port:       existing.Exit.Port,
					TunnelUUID: existing.Exit.TunnelUUID,
					Priority:   100,
					Enabled:    exits.BootstrapEnabledPtr(true),
				})
			}
			for i := range p.Exits {
				if strings.TrimSpace(p.Exits[i].TunnelUUID) == "" {
					p.Exits[i].TunnelUUID = resolveExitTunnelUUID(
						renderOpts.PriorBootstrap,
						p.SSH.User,
						p.Exits[i].SSHHost,
						p.SSH.Identity,
						p.Bridge.RemoteDir,
						p.Exits[i].DialAddr,
						p.Exits[i].Port,
					)
				}
			}
		}
	}
	ds, err := installplan.RenderDesiredStateWithOptions(p, renderOpts)
	exitOnErr("apply render", err)

	projectRoot := p.Artifacts.ProjectRoot
	relayBin := p.Artifacts.RelayBinary
	if relayBin == "" {
		relayBin = "ultra-relay-linux-amd64"
	}
	systemdLocal, cleanupUnit := relaySystemdUnitPath(projectRoot)
	defer cleanupUnit()
	exitOnErr("apply relay binary", fileMustExist(relayBin))

	if p.Database.Enabled && ds.PostgresConfig != nil {
		setupPlanDatabase(p, ds, format)
	}

	emitInstallEvent(format, installplan.EventStep, "", "configuring bridge system", "bridge")
	exitOnErr("bridge system setup", install.SetupSystem(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity))
	bridgePrep := fmt.Sprintf(
		`set -euo pipefail; REMOTE_DIR=%q; mkdir -p "$REMOTE_DIR" && chmod 700 "$REMOTE_DIR"; id -u ultra-relay >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin ultra-relay`,
		p.Bridge.RemoteDir,
	)
	exitOnErr("bridge prepare", install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, bridgePrep))
	if !p.Features.SkipGeoDownload && ds.BridgeSpecObject.SplitRoutingEnabled() {
		emitInstallEvent(format, installplan.EventStep, "", "installing bridge geo assets", "bridge")
		geoScript := install.RunetfreedomGeoRemoteScript(ds.BridgeSpecObject.GeoAssetsDir, p.Features.GeoReleaseTag)
		exitOnErr("bridge geo download", install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, geoScript))
	}

	common := exitDeployCommon{
		sshUser:      p.SSH.User,
		identity:     p.SSH.Identity,
		remoteDir:    p.Bridge.RemoteDir,
		binaryPath:   relayBin,
		systemdLocal: systemdLocal,
		logLevel:     p.Features.LogLevel,
		mimicHost:    ds.SplitHTTPHost,
		genExitTLS:   p.Features.GenerateExitTLS,
		warp:         p.Features.WARP,
		warpPort:     p.Features.WARPPort,
	}
	plans := make([]exitDeployPlan, 0, len(p.Exits))
	for _, ex := range p.Exits {
		plans = append(plans, exitDeployPlan{
			Label:      ex.Name,
			SSHHost:    ex.SSHHost,
			DialAddr:   ex.DialAddr,
			Port:       ex.Port,
			Name:       ex.Name,
			Priority:   ex.Priority,
			TunnelUUID: ds.TunnelUUIDs[ex.Name],
			SpecJSON:   ds.ExitSpecs[ex.Name],
		})
	}
	outcomes := make(map[string]exitDeployOutcome, len(plans))
	for _, plan := range plans {
		if !install.SSHReachable(common.sshUser, plan.SSHHost, common.identity) {
			msg := fmt.Sprintf("exit %s (%s) is not reachable; deploy skipped", plan.Label, plan.SSHHost)
			emitInstallEvent(format, installplan.EventWarning, installplan.CodeSSHUnreachable, msg, plan.Label)
			outcomes[plan.Label] = exitDeployOutcome{}
			continue
		}
		emitInstallEvent(format, installplan.EventStep, "", fmt.Sprintf("deploying exit %s", plan.SSHHost), plan.Label)
		certPin, err := deployExitNode(common, plan)
		if err != nil {
			emitInstallEvent(format, installplan.EventWarning, "", fmt.Sprintf("exit deploy failed: %v", err), plan.Label)
			outcomes[plan.Label] = exitDeployOutcome{}
			continue
		}
		outcomes[plan.Label] = exitDeployOutcome{Deployed: true, CertPin: certPin}
	}
	if countDeployedOutcomes(outcomes) == 0 {
		emitInstallEvent(format, installplan.EventError, installplan.CodeNoExitDeployed, "no exit nodes were deployed", "")
		os.Exit(1)
	}
	bootstrapEntries := buildBootstrapEntries(plans, nil, outcomes)
	bootstrapJSON, err := json.MarshalIndent(bootstrapEntries, "", "  ")
	exitOnErr("bootstrap", err)
	deployBridgeArtifacts(p, ds, relayBin, systemdLocal, bootstrapJSON, format)
	if p.Bot.Enabled {
		deployBotPlan(p, format)
	}
	emitInstallEvent(format, installplan.EventStep, "", "install finished", "")
}

func loadPlanRemoteBridgeSpec(p *installplan.InstallPlan) (*config.Spec, error) {
	remoteSpec := path.Join(p.Bridge.RemoteDir, "spec.json")
	out, err := install.RunSSHOutput(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, fmt.Sprintf(`cat %q`, remoteSpec))
	if err != nil {
		return nil, err
	}
	out = bytes.TrimSpace(out)
	if len(out) == 0 {
		return nil, fmt.Errorf("empty remote spec")
	}
	var spec config.Spec
	if err := json.Unmarshal(out, &spec); err != nil {
		return nil, err
	}
	if spec.Role != config.RoleBridge {
		return nil, fmt.Errorf("remote spec role is %q, not bridge", spec.Role)
	}
	return &spec, nil
}

func loadPlanRemoteAdminToken(p *installplan.InstallPlan) string {
	envPath := path.Join(p.Bridge.RemoteDir, "environment")
	envScript := fmt.Sprintf(`grep -E '^ULTRA_RELAY_ADMIN_TOKEN=' %q 2>/dev/null | head -1 || true`, envPath)
	out, err := install.RunSSHOutput(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, envScript)
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(bytes.TrimSpace(out)))
	if strings.HasPrefix(line, "ULTRA_RELAY_ADMIN_TOKEN=") {
		return strings.TrimSpace(strings.TrimPrefix(line, "ULTRA_RELAY_ADMIN_TOKEN="))
	}
	return ""
}

func applyRemotePlan(p *installplan.InstallPlan, releaseDir string, format string) {
	if releaseDir == "" {
		releaseDir = "/opt/ultra/current"
	}
	p.Artifacts.ProjectRoot = ""
	p.Artifacts.RelayBinary = filepath.Join(releaseDir, "ultra-relay")
	p.Artifacts.BotBinary = filepath.Join(releaseDir, "ultra-bot")
	applyPlanN(p, format)
}

func setupPlanDatabase(p *installplan.InstallPlan, ds *installplan.DesiredState, format string) {
	dbSSH := p.Database.SSHUser
	if dbSSH == "" {
		dbSSH = p.SSH.User
	}
	primaryHost := p.Database.PrimaryHost
	if primaryHost == "" {
		primaryHost = p.Bridge.SSHHost
	}
	replicaHost := p.Database.ReplicaHost
	if replicaHost == "" && len(p.Exits) > 0 {
		replicaHost = p.Exits[0].SSHHost
	}
	emitInstallEvent(format, installplan.EventStep, "", fmt.Sprintf("setting up PostgreSQL primary on %s", primaryHost), "database")
	exitOnErr("postgres primary system setup", install.SetupSystem(dbSSH, primaryHost, p.SSH.Identity))
	exitOnErr("postgres primary setup", install.SetupPrimaryPostgres(dbSSH, primaryHost, p.SSH.Identity, *ds.PostgresConfig))
	if replicaHost != "" && replicaHost != primaryHost {
		if !install.SSHReachable(dbSSH, replicaHost, p.SSH.Identity) {
			emitInstallEvent(
				format,
				installplan.EventWarning,
				installplan.CodeSSHUnreachable,
				fmt.Sprintf("PostgreSQL replica %s is not reachable; skipping", replicaHost),
				"database",
			)
			return
		}
		emitInstallEvent(format, installplan.EventStep, "", fmt.Sprintf("setting up PostgreSQL replica on %s", replicaHost), "database")
		if err := install.SetupSystem(dbSSH, replicaHost, p.SSH.Identity); err != nil {
			emitInstallEvent(
				format,
				installplan.EventWarning,
				installplan.CodeSSHUnreachable,
				fmt.Sprintf("replica system setup failed: %v", err),
				"database",
			)
			return
		}
		if err := install.SetupReplicaPostgres(dbSSH, replicaHost, p.SSH.Identity, *ds.PostgresConfig, primaryHost); err != nil {
			emitInstallEvent(
				format,
				installplan.EventWarning,
				installplan.CodeRemotePackageInstallFailed,
				fmt.Sprintf("replica setup failed: %v", err),
				"database",
			)
		}
	}
}

func deployBridgeArtifacts(
	p *installplan.InstallPlan,
	ds *installplan.DesiredState,
	relayBin string,
	systemdLocal string,
	bootstrapJSON []byte,
	format string,
) {
	emitInstallEvent(format, installplan.EventStep, "", "uploading bridge artifacts", "bridge")
	tmpBridge := filepath.Join(os.TempDir(), "ultra-plan-bridge-spec.json")
	tmpBootstrap := filepath.Join(os.TempDir(), exits.BootstrapFileName)
	tmpEnv := filepath.Join(os.TempDir(), "ultra-plan-relay.env")
	exitOnErr("tmp bridge spec", os.WriteFile(tmpBridge, ds.BridgeSpec, 0o600))
	exitOnErr("tmp bootstrap", os.WriteFile(tmpBootstrap, bootstrapJSON, 0o600))
	exitOnErr("tmp bridge env", os.WriteFile(tmpEnv, []byte(ds.BridgeEnv), 0o600))
	defer func() {
		_ = os.Remove(tmpBridge)
		_ = os.Remove(tmpBootstrap)
		_ = os.Remove(tmpEnv)
	}()
	for _, fn := range []func() error{
		func() error {
			return install.SCP(p.SSH.Identity, relayBin, p.SSH.User, p.Bridge.SSHHost, "/tmp/ultra-relay")
		},
		func() error {
			return install.SCP(p.SSH.Identity, tmpBridge, p.SSH.User, p.Bridge.SSHHost, path.Join(p.Bridge.RemoteDir, "spec.json"))
		},
		func() error {
			return install.SCP(p.SSH.Identity, tmpBootstrap, p.SSH.User, p.Bridge.SSHHost, path.Join(p.Bridge.RemoteDir, exits.BootstrapFileName))
		},
		func() error {
			return install.SCP(p.SSH.Identity, tmpEnv, p.SSH.User, p.Bridge.SSHHost, path.Join(p.Bridge.RemoteDir, "environment.tmp"))
		},
	} {
		exitOnErr("bridge scp", fn())
	}
	finalize := fmt.Sprintf(`set -euo pipefail
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
`, p.Bridge.RemoteDir, exits.BootstrapFileName)
	exitOnErr("bridge finalize", install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, finalize))
	ports := []int{ds.BridgeSpecObject.VLESSPort}
	if ds.BridgeSpecObject.AntiCensor != nil && ds.BridgeSpecObject.AntiCensor.PublicXHTTPPort > 0 {
		ports = append(ports, ds.BridgeSpecObject.AntiCensor.PublicXHTTPPort)
	}
	exitOnErr("bridge firewall", install.SetupFirewallPorts(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, ports))
	exitOnErr("bridge unit scp", install.SCP(p.SSH.Identity, systemdLocal, p.SSH.User, p.Bridge.SSHHost, "/tmp/ultra-relay.service"))
	unitMv := `mv /tmp/ultra-relay.service /etc/systemd/system/ultra-relay.service && systemctl daemon-reload && systemctl enable ultra-relay && systemctl restart ultra-relay`
	exitOnErr("bridge systemctl", install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, unitMv))
}

func deployBotPlan(p *installplan.InstallPlan, format string) {
	botBin := p.Artifacts.BotBinary
	if botBin == "" {
		botBin = "ultra-bot-linux-amd64"
	}
	if err := fileMustExist(botBin); err != nil {
		emitInstallEvent(format, installplan.EventWarning, "", fmt.Sprintf("bot binary not found, skipping bot deploy: %v", err), "bot")
		return
	}
	envFile := p.SecretsEnvFile()
	if err := fileMustExist(envFile); err != nil {
		emitInstallEvent(
			format,
			installplan.EventError,
			installplan.CodeMissingBotToken,
			fmt.Sprintf("secrets env file missing: %v", err),
			"bot",
		)
		os.Exit(1)
	}
	projectRoot := p.Artifacts.ProjectRoot
	unit, cleanupUnit := botSystemdUnitPath(projectRoot)
	defer cleanupUnit()
	emitInstallEvent(format, installplan.EventStep, "", "deploying ultra-bot", "bot")
	_ = install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, "systemctl stop ultra-bot 2>/dev/null || true")
	exitOnErr("bot binary scp", install.SCP(p.SSH.Identity, botBin, p.SSH.User, p.Bridge.SSHHost, "/usr/local/bin/ultra-bot"))
	exitOnErr("bot chmod", install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, "chmod 755 /usr/local/bin/ultra-bot"))
	exitOnErr("bot env scp", install.SCP(p.SSH.Identity, envFile, p.SSH.User, p.Bridge.SSHHost, "/etc/ultra-relay/bot.env"))
	exitOnErr("bot env chmod", install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, "chmod 600 /etc/ultra-relay/bot.env"))
	envScript := fmt.Sprintf(`
grep -v '^ULTRA_BOT_' /etc/ultra-relay/environment > /tmp/env.tmp 2>/dev/null || true
{
  printf 'ULTRA_BOT_DOMAIN=%%s\n' %s
  printf 'ULTRA_BOT_PORT=%d\n'
  printf 'ULTRA_BOT_TELEGRAM_SOCKS5=127.0.0.1:10809\n'
} >> /tmp/env.tmp
mv /tmp/env.tmp /etc/ultra-relay/environment
chmod 600 /etc/ultra-relay/environment
`, shellLiteral(p.Bot.Domain), p.Bot.Port)
	exitOnErr("bot env update", install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, envScript))
	if err := obtainBotCertPlan(p); err != nil {
		emitInstallEvent(format, installplan.EventWarning, installplan.CodeCertbotFailed, fmt.Sprintf("bot cert failed: %v", err), "bot")
	}
	exitOnErr("bot unit scp", install.SCP(p.SSH.Identity, unit, p.SSH.User, p.Bridge.SSHHost, "/etc/systemd/system/ultra-bot.service"))
	start := `mkdir -p /var/lib/ultra-bot && systemctl daemon-reload && systemctl enable ultra-bot && systemctl restart ultra-bot`
	exitOnErr("bot systemctl", install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, start))
	invite, err := randomInviteToken()
	exitOnErr("bot invite token", err)
	insert := fmt.Sprintf(`
_dsn=$(python3 -c "import json; d=json.load(open('/etc/ultra-relay/spec.json')); print(d.get('database',{}).get('dsn',''))" 2>/dev/null || true)
if [[ -n "$_dsn" ]]; then
  psql "$_dsn" -c "INSERT INTO bot_invite_tokens(token) VALUES('%s') ON CONFLICT DO NOTHING" >/dev/null 2>&1 || true
fi
`, invite)
	_ = install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, insert)
	emitInstallEvent(format, installplan.EventLog, "", "telegram admin invite: /start "+invite, "bot")
}

func relaySystemdUnitPath(projectRoot string) (string, func()) {
	if projectRoot != "" {
		p := filepath.Join(projectRoot, "deploy/systemd/ultra-relay.service")
		if _, err := os.Stat(p); err == nil {
			return p, func() {}
		}
	}
	return tempUnitPath("ultra-relay.service", install.RelaySystemdUnit)
}

func botSystemdUnitPath(projectRoot string) (string, func()) {
	if projectRoot != "" {
		p := filepath.Join(projectRoot, "deploy/systemd/ultra-bot.service")
		if _, err := os.Stat(p); err == nil {
			return p, func() {}
		}
	}
	return tempUnitPath("ultra-bot.service", install.BotSystemdUnit)
}

func tempUnitPath(name, content string) (string, func()) {
	p := filepath.Join(os.TempDir(), "ultra-"+name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		exitOnErr("write embedded systemd unit", err)
	}
	return p, func() { _ = os.Remove(p) }
}

func obtainBotCertPlan(p *installplan.InstallPlan) error {
	domain := p.Bot.Domain
	checkFresh := fmt.Sprintf(
		`cert=/etc/letsencrypt/live/%s/fullchain.pem; [[ -f "$cert" ]] && openssl x509 -checkend 604800 -noout -in "$cert" >/dev/null 2>&1`,
		shellLiteral(domain),
	)
	if install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, checkFresh) == nil {
		return nil
	}
	prep := `set -e
if ! command -v certbot >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get update -q
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q certbot
fi
systemctl stop ultra-bot 2>/dev/null || true`
	if err := install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, prep); err != nil {
		return err
	}
	cmd := fmt.Sprintf(
		`certbot certonly --standalone -d %s --non-interactive --agree-tos --email %s`,
		shellLiteral(domain),
		shellLiteral("admin@"+domain),
	)
	return install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, cmd)
}

func shellLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func randomInviteToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func fileMustExist(path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	return nil
}
