package installplan

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/loglevel"
)

// ValidatePlan accepts only the complete operator installation schema.
func ValidatePlan(p *InstallPlan) error {
	return validatePlan(p, false)
}

// ValidateBootstrapPlan rejects lifecycle projections even when explicit budgets
// would otherwise let their serialized form pass ordinary plan validation.
func ValidateBootstrapPlan(p *InstallPlan) error {
	if p != nil && p.LifecycleOnly {
		return errors.New("lifecycle plan cannot be used for bootstrap or apply")
	}
	return ValidatePlan(p)
}

// localProjection is private to host-local runtime projection. Its historical
// v1 in-process data shape carries no deployment policy and is never an install.
func validatePlan(p *InstallPlan, localProjection bool) error {
	if p == nil {
		return errors.New("install plan is nil")
	}
	if p.LifecycleOnly &&
		(p.Secrets.DatabaseDumpFile != "" || p.Secrets.DatabaseDumpSHA256 != "" || p.SourceValues["DATABASE_DUMP"] != "" ||
			p.Secrets.DatabaseTunnelPrivateKeyFile != "" || p.Secrets.DatabaseTunnelPrivateKeySHA256 != "" || p.SourceValues["DB_TUNNEL_PRIVATE_KEY_FILE"] != "") {
		return errors.New("lifecycle plan must not contain bootstrap archive inputs")
	}
	if p.AdoptRuntime && (!p.FullAutomation() || !p.Bridge.ReuseSpec) {
		return errors.New("runtime adoption requires schema 2 and an existing bridge")
	}
	if localProjection {
		if p.SchemaVersion != 1 || p.Automation != nil || p.AdoptRuntime {
			return errors.New("invalid host-local runtime projection envelope")
		}
	} else if p.SchemaVersion != CurrentSchemaVersion {
		return fmt.Errorf("only install plan schema_version %d is supported (received %d)", CurrentSchemaVersion, p.SchemaVersion)
	}
	if err := validateAutomation(p); err != nil {
		return err
	}
	return validatePlanRoles(p)
}

// validatePlanRoles is shared with read-only adoption preparation. Callers that
// deploy a plan must first enforce its schema and complete automation policy.
func validatePlanRoles(p *InstallPlan) error {
	if p.Secrets.DatabaseTunnelPrivateKeyFile != "" || p.Secrets.DatabaseTunnelPrivateKeySHA256 != "" {
		if !p.Database.Enabled {
			return errors.New("DB_TUNNEL_PRIVATE_KEY_FILE requires a dedicated database")
		}
		if err := VerifyDatabaseTunnelPrivateKey(p.Secrets.DatabaseTunnelPrivateKeyFile, p.Secrets.DatabaseTunnelPrivateKeySHA256); err != nil {
			return err
		}
	}
	if strings.TrimSpace(p.SSH.User) == "" {
		p.SSH.User = "root"
	}
	if p.SSH.ConnectTimeoutSec == 0 {
		p.SSH.ConnectTimeoutSec = 10
	}
	if strings.TrimSpace(p.Bridge.Address) == "" {
		p.Bridge.Address = p.Bridge.SSHHost
	}
	if strings.TrimSpace(p.Bridge.SSHHost) == "" {
		p.Bridge.SSHHost = p.Bridge.Address
	}
	if strings.TrimSpace(p.Bridge.SSHHost) == "" {
		return errors.New("bridge.ssh_host is required")
	}
	if strings.TrimSpace(p.Bridge.PublicHost) == "" {
		p.Bridge.PublicHost = p.Bridge.Address
	}
	if p.Bridge.VLESSPort == 0 {
		p.Bridge.VLESSPort = 443
	}
	if err := validatePort("bridge.vless_port", p.Bridge.VLESSPort); err != nil {
		return err
	}
	if p.Bridge.TunnelPort == 0 {
		p.Bridge.TunnelPort = p.Bridge.VLESSPort
	}
	if err := validatePort("bridge.tunnel_port", p.Bridge.TunnelPort); err != nil {
		return err
	}
	if strings.TrimSpace(p.Bridge.RemoteDir) == "" {
		p.Bridge.RemoteDir = "/etc/ultra-relay"
	}
	if strings.TrimSpace(p.Bridge.AdminListen) == "" {
		p.Bridge.AdminListen = "127.0.0.1:8443"
	}
	if !p.Bridge.ReuseSpec {
		if strings.TrimSpace(p.Bridge.RealityDest) == "" {
			return errors.New("bridge.reality_dest is required unless bridge.reuse_spec=true")
		}
		if _, _, err := net.SplitHostPort(p.Bridge.RealityDest); err != nil {
			return errors.New("bridge.reality_dest must be host:port")
		}
	}
	if len(p.Exits) == 0 {
		return errors.New("at least one exit node is required")
	}
	seenExitHosts := make(map[string]bool, len(p.Exits))
	seenExitNames := make(map[string]bool, len(p.Exits))
	for i := range p.Exits {
		e := &p.Exits[i]
		if strings.TrimSpace(e.SSHHost) == "" {
			return fmt.Errorf("exits[%d].ssh_host is required", i)
		}
		if seenExitHosts[e.SSHHost] {
			return fmt.Errorf("duplicate exit ssh_host %q", e.SSHHost)
		}
		seenExitHosts[e.SSHHost] = true
		if strings.TrimSpace(e.Name) == "" {
			if i == 0 {
				e.Name = "primary"
			} else {
				e.Name = fmt.Sprintf("exit-%d", i+1)
			}
		}
		if seenExitNames[e.Name] {
			return fmt.Errorf("duplicate exit name %q", e.Name)
		}
		seenExitNames[e.Name] = true
		if strings.TrimSpace(e.DialAddr) == "" {
			e.DialAddr = e.SSHHost
		}
		if e.Port == 0 {
			e.Port = p.Bridge.TunnelPort
		}
		if err := validatePort(fmt.Sprintf("exits[%d].port", i), e.Port); err != nil {
			return err
		}
		if e.Priority == 0 {
			e.Priority = 100 + i*100
		}
	}
	if domain := p.Features.MainExitDomain; domain != "" {
		if net.ParseIP(domain) != nil || !validTunnelDomain(domain) || strings.ToLower(domain) != domain {
			return errors.New("MAIN_EXIT_DOMAIN must be a lowercase DNS hostname")
		}
		if len(p.Exits) != 1 || net.ParseIP(p.Exits[0].SSHHost).To4() == nil || p.Exits[0].DialAddr != p.Exits[0].SSHHost {
			return errors.New("managed tunnel TLS requires one exit dialed by its explicit IP")
		}
		if p.Exits[0].Port == 80 {
			return errors.New("managed tunnel TLS requires TUNNEL_PORT other than 80; HTTP-01 nginx occupies TCP/80")
		}
		if p.AdoptRuntime || p.Bridge.ReuseSpec {
			return errors.New("managed tunnel TLS requires fresh bootstrap with REUSE_BRIDGE_SPEC=false")
		}
		if p.Automation == nil || p.Automation.DNS == nil || p.Automation.Ingress == nil || p.Automation.Ingress.ForwardHost != "" {
			return errors.New("managed tunnel TLS requires schema 2 direct ingress and managed DNS")
		}
		zone := p.Automation.DNS.Zone
		label := strings.TrimSuffix(domain, "."+zone)
		if domain == label || strings.Contains(label, ".") || label == p.Automation.DNS.SubscriptionName ||
			label == p.Automation.DNS.VPNName ||
			domain == p.Bot.Domain {
			return errors.New("MAIN_EXIT_DOMAIN must be a distinct single label in DNS_ZONE")
		}
		p.Features.Preset = "standard"
		p.Features.Transport = string(config.TunnelTransportSplitHTTP)
		p.Features.GenerateExitTLS = false
		p.Features.SplitHTTPHost = domain
		if p.Features.SplitHTTPPath == "" {
			p.Features.SplitHTTPPath = "/ultra-xhttp"
		}
	}
	if strings.TrimSpace(p.Features.Preset) == "" || p.Features.Preset == "plusgaming" {
		p.Features.Preset = "apijson"
	}
	if p.Features.Preset != "apijson" && p.Features.Preset != "steamlike" && p.Features.Preset != "standard" {
		return errors.New("features.preset is unsupported")
	}
	if strings.TrimSpace(p.Features.Transport) == "" {
		p.Features.Transport = string(config.TunnelTransportSplitHTTP)
	}
	if p.Features.Transport != string(config.TunnelTransportSplitHTTP) && p.Features.Transport != string(config.TunnelTransportGRPC) {
		return errors.New("features.transport must be splithttp or grpc")
	}
	if p.Features.RoutingMode != "" && p.Features.RoutingMode != config.RoutingModeBlocklist &&
		p.Features.RoutingMode != config.RoutingModeRUDirect {
		return errors.New("features.routing_mode must be blocklist or ru_direct")
	}
	if strings.TrimSpace(p.Features.LogLevel) == "" {
		p.Features.LogLevel = "info"
	}
	if _, _, err := loglevel.ParseRelayLogLevel(p.Features.LogLevel); err != nil {
		return err
	}
	if p.Features.WARPPort == 0 {
		p.Features.WARPPort = 40000
	}
	if p.Features.VLESSFlow == "" {
		p.Features.VLESSFlow = config.DefaultVLESSFlow
	}
	if p.Bot.Enabled {
		if strings.TrimSpace(p.Bot.Domain) == "" {
			return errors.New("bot.domain is required when bot.enabled=true")
		}
		if p.Bot.Port == 0 {
			p.Bot.Port = 8444
		}
		if err := validatePort("bot.port", p.Bot.Port); err != nil {
			return err
		}
	}
	if p.Secrets.DatabaseDumpFile != "" && (!p.Database.Enabled || p.Bridge.ReuseSpec || p.AdoptRuntime) {
		return errors.New("DATABASE_DUMP requires a dedicated database and fresh bootstrap without REUSE_BRIDGE_SPEC")
	}
	if p.AdoptRuntime && p.Database.Enabled {
		return errors.New(
			"legacy runtime adoption is unavailable for dedicated databases; use an explicitly reviewed bootstrap with reuse_spec",
		)
	}
	if p.Database.ReplicaHost != "" {
		return errors.New("database replicas are no longer supported; use a dedicated DB_HOST")
	}
	if p.Database.RepairAppCredentials && !p.Database.Enabled {
		return errors.New("DB_REPAIR_APP_CREDENTIALS requires DATABASE_IP")
	}
	if p.Database.Enabled {
		if net.ParseIP(p.Database.PrimaryHost).To4() == nil || p.Database.PrimaryHost == p.Bridge.Address ||
			p.Database.PrimaryHost == p.Bridge.SSHHost {
			return errors.New("database.primary_host must be the IP of a dedicated database server")
		}
		for _, exit := range p.Exits {
			if p.Database.PrimaryHost == exit.SSHHost || p.Database.PrimaryHost == exit.DialAddr {
				return errors.New("database server must be separate from VPN exit hosts")
			}
		}
		if p.Database.SSHUser == "" {
			p.Database.SSHUser = p.SSH.User
		}
		if p.Database.SSHIdentity == "" {
			p.Database.SSHIdentity = p.SSH.Identity
		}
		if p.Database.Name == "" {
			p.Database.Name = "ultra_db"
		}
		if p.Database.User == "" {
			p.Database.User = "ultra"
		}
	}
	if p.Verification.Enabled && strings.TrimSpace(p.Verification.IPURL) == "" {
		return errors.New("verification.ip_url is required when verification.enabled=true")
	}
	if p.Verification.FailLogLines == 0 {
		p.Verification.FailLogLines = 400
	}
	return nil
}

func validatePort(name string, port int) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("%s must be 1..65535", name)
	}
	return nil
}

func validTunnelDomain(name string) bool {
	if len(name) > 253 || !strings.Contains(name, ".") {
		return false
	}
	label := regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	for _, part := range strings.Split(name, ".") {
		if !label.MatchString(part) {
			return false
		}
	}
	return true
}
