package installplan

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/loglevel"
)

func ValidatePlan(p *InstallPlan) error {
	if p == nil {
		return errors.New("install plan is nil")
	}
	if p.SchemaVersion == 0 {
		p.SchemaVersion = CurrentSchemaVersion
	}
	if p.SchemaVersion != CurrentSchemaVersion {
		return fmt.Errorf("unsupported install plan schema_version %d", p.SchemaVersion)
	}
	if strings.TrimSpace(p.SSH.User) == "" {
		p.SSH.User = "root"
	}
	if p.SSH.ConnectTimeoutSec == 0 {
		p.SSH.ConnectTimeoutSec = 10
	}
	if strings.TrimSpace(p.Bridge.SSHHost) == "" {
		return errors.New("bridge.ssh_host is required")
	}
	if strings.TrimSpace(p.Bridge.PublicHost) == "" {
		p.Bridge.PublicHost = p.Bridge.SSHHost
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
	if strings.TrimSpace(p.Features.Preset) == "" || p.Features.Preset == "plusgaming" {
		p.Features.Preset = "apijson"
	}
	if p.Features.Preset != "apijson" && p.Features.Preset != "steamlike" {
		return errors.New("features.preset must be apijson or steamlike")
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
	if p.Database.Enabled {
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
