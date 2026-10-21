package installplan

import (
	"encoding/json"
	"errors"
	"net"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/config"
)

// ProjectLocalManagedTunnelRuntime is a pure preservation primitive, not an
// authorization to upgrade. Its caller must independently attest the live fleet,
// freeze renewal, bind the local certificate pair and renewal configuration to
// the operation, and prove rollback and recovery before applying its output.
// The ordinary installation/adoption validation and upgrade guards stay intact.
func ProjectLocalManagedTunnelRuntime(p *InstallPlan, raw []byte, role config.Role, nodeName string) (*LocalRuntimeProjection, error) {
	if p == nil || p.SourceValues == nil || p.SchemaVersion != 1 || p.Automation != nil || p.AdoptRuntime {
		return nil, errors.New("invalid managed tunnel preservation envelope")
	}
	// Validate all ordinary local inputs on a private copy. The managed domain
	// is validated against the installed spec below, rather than bootstrap's
	// incompatible requirement for fresh credentials and complete DNS policy.
	data, err := json.Marshal(p)
	if err != nil {
		return nil, errors.New("invalid managed tunnel preservation envelope")
	}
	var local InstallPlan
	if json.Unmarshal(data, &local) != nil {
		return nil, errors.New("invalid managed tunnel preservation envelope")
	}
	domain := local.Features.MainExitDomain
	local.SourceValues = p.SourceValues
	local.Features.MainExitDomain = ""
	checked, err := validatedRuntimePlan(&local, true)
	if err != nil {
		return nil, err
	}
	checked.Features.MainExitDomain = domain
	var previous config.Spec
	if json.Unmarshal(raw, &previous) != nil {
		return nil, errors.New("invalid managed tunnel preservation specification")
	}
	if err = validateManagedTunnelProjection(checked, &previous, nodeName); err != nil {
		return nil, err
	}
	return projectLocalRuntime(checked, raw, role, nodeName)
}

func validateManagedTunnelProjection(p *InstallPlan, previous *config.Spec, node string) error {
	fail := func() error { return errors.New("managed tunnel preservation identity mismatch") }
	domain := p.Features.MainExitDomain
	if domain == "" || !validTunnelDomain(domain) || domain != strings.ToLower(domain) || net.ParseIP(domain) != nil ||
		len(p.Exits) != 1 || p.Features.GenerateExitTLS || p.Features.Preset != "standard" ||
		p.Features.Transport != string(config.TunnelTransportSplitHTTP) || p.Features.SplitHTTPHost != domain ||
		previous.TunnelTLSProvision != config.TunnelTLSACME || previous.MimicPreset != "standard" ||
		previous.TunnelTransport != config.TunnelTransportSplitHTTP || previous.SplithttpHost != domain ||
		previous.SplitHTTPTLS.ServerName != domain || previous.SplitHTTPTLS.OmitSNI ||
		(previous.SplitHTTPTLS.SNIMode != "" && previous.SplitHTTPTLS.SNIMode != "auto" && previous.SplitHTTPTLS.SNIMode != "send") ||
		previous.Exit.PinnedPeerCertSHA256 != "" || p.Features.SplitHTTPPath != previous.SplithttpPath {
		return fail()
	}
	ex := p.Exits[0]
	if net.ParseIP(ex.SSHHost).To4() == nil || ex.DialAddr != ex.SSHHost || ex.Port == 80 ||
		(ex.TunnelUUID != "" && ex.TunnelUUID != previous.Exit.TunnelUUID) {
		return fail()
	}
	switch previous.Role {
	case config.RoleBridge:
		if previous.Exit.Address != ex.DialAddr || previous.Exit.Port != ex.Port {
			return fail()
		}
	case config.RoleExit:
		if node != ex.Name || previous.VLESSPort != ex.Port ||
			previous.ExitCertPaths.CertFile != "/etc/ultra-relay/fullchain.pem" ||
			previous.ExitCertPaths.KeyFile != "/etc/ultra-relay/privkey.pem" {
			return fail()
		}
	default:
		return fail()
	}
	return nil
}
