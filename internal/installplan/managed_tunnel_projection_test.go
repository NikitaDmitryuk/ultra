package installplan

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/config"
)

func managedTunnelProjectionFixture(t *testing.T, role config.Role) (*InstallPlan, []byte, string) {
	t.Helper()
	p, opts := projectionFixture(t)
	p.SchemaVersion, p.Automation, p.AdoptRuntime = 1, nil, false
	p.Bridge.ReuseSpec = true
	p.Features.MainExitDomain = "tunnel.example.com"
	p.Features.SplitHTTPHost = p.Features.MainExitDomain
	p.Features.SplitHTTPPath = "/ultra-xhttp"
	p.Features.Preset = "standard"
	p.Features.Transport = "splithttp"
	p.Features.GenerateExitTLS = false
	p.Exits[0].DialAddr = p.Exits[0].SSHHost
	previous, node := *opts.ExistingBridge, ""
	if role == config.RoleExit {
		previous, node = *opts.ExistingExits["primary"], "primary"
	}
	previous.TunnelTLSProvision = config.TunnelTLSACME
	previous.TunnelTransport = config.TunnelTransportSplitHTTP
	previous.MimicPreset = "standard"
	previous.SplithttpHost = p.Features.MainExitDomain
	previous.SplithttpPath = p.Features.SplitHTTPPath
	previous.SplitHTTPTLS.ServerName = p.Features.MainExitDomain
	previous.SplitHTTPTLS.SNIMode = "send"
	previous.Exit.Address = p.Exits[0].DialAddr
	previous.Exit.PinnedPeerCertSHA256 = ""
	previous.ExitCertPaths = config.CertPaths{CertFile: "/etc/ultra-relay/fullchain.pem", KeyFile: "/etc/ultra-relay/privkey.pem"}
	raw, err := json.Marshal(previous)
	if err != nil {
		t.Fatal(err)
	}
	return p, raw, node
}

func TestManagedTunnelProjectionPreservesTrustAndUnknownTLS(t *testing.T) {
	for _, role := range []config.Role{config.RoleBridge, config.RoleExit} {
		t.Run(string(role), func(t *testing.T) {
			p, raw, node := managedTunnelProjectionFixture(t, role)
			doc, _ := runtimeDocument(raw)
			tls := runtimeObject(doc, "splithttp_tls")
			runtimeSet(tls, "future_policy", map[string]any{"strict": true})
			runtimeSet(doc, "splithttp_tls", tls)
			raw, _ = json.Marshal(doc)
			p.Features.LogLevel = "debug"
			p.Features.DisableDOH = !p.Features.DisableDOH
			before, _ := json.Marshal(p)
			projected, err := ProjectLocalManagedTunnelRuntime(p, raw, role, node)
			if err != nil {
				t.Fatal(err)
			}
			after, _ := runtimeDocument(projected.SpecJSON)
			for _, key := range []string{"splithttp_tls", "tunnel_tls_provision", "exit_cert", "exit"} {
				if !equalJSONValue(doc[key], after[key]) {
					t.Fatalf("preserved identity changed: %s", key)
				}
			}
			if !strings.Contains(string(projected.SpecJSON), "future_policy") {
				t.Fatal("unknown TLS policy lost")
			}
			for _, transition := range projected.Transitions {
				if transition.Kind == RuntimeTransitionTLS || transition.Kind == RuntimeTransitionTunnel {
					t.Fatalf("same identity requires unexpected tunnel effects: %v", projected.Transitions)
				}
			}
			planAfter, _ := json.Marshal(p)
			if string(before) != string(planAfter) {
				t.Fatal("projection mutated request")
			}
			// The primitive must not relax ordinary deployment/adoption policy.
			if ValidateLocalRuntimePlan(p) == nil {
				t.Fatal("managed preservation bypassed ordinary local validation")
			}
		})
	}
}

func TestManagedTunnelProjectionRejectsIdentityChanges(t *testing.T) {
	changes := map[string]func(*InstallPlan, *config.Spec){
		"missing domain":     func(p *InstallPlan, _ *config.Spec) { p.Features.MainExitDomain = "" },
		"changed domain":     func(p *InstallPlan, _ *config.Spec) { p.Features.MainExitDomain = "other.example.com" },
		"host":               func(_ *InstallPlan, s *config.Spec) { s.SplithttpHost = "other.example.com" },
		"sni":                func(_ *InstallPlan, s *config.Spec) { s.SplitHTTPTLS.ServerName = "other.example.com" },
		"omit sni":           func(_ *InstallPlan, s *config.Spec) { s.SplitHTTPTLS.OmitSNI = true },
		"unknown sni policy": func(_ *InstallPlan, s *config.Spec) { s.SplitHTTPTLS.SNIMode = "future" },
		"pin":                func(_ *InstallPlan, s *config.Spec) { s.Exit.PinnedPeerCertSHA256 = strings.Repeat("a", 64) },
		"provision":          func(_ *InstallPlan, s *config.Spec) { s.TunnelTLSProvision = config.TunnelTLSUserProv },
		"path":               func(p *InstallPlan, _ *config.Spec) { p.Features.SplitHTTPPath = "/changed" },
		"transport":          func(p *InstallPlan, _ *config.Spec) { p.Features.Transport = "grpc" },
		"rotate certificate": func(p *InstallPlan, _ *config.Spec) { p.Features.GenerateExitTLS = true },
		"port":               func(p *InstallPlan, _ *config.Spec) { p.Exits[0].Port++ },
		"exit identity":      func(p *InstallPlan, _ *config.Spec) { p.Exits[0].TunnelUUID = "changed" },
		"cert path":          func(_ *InstallPlan, s *config.Spec) { s.ExitCertPaths.CertFile = "/tmp/cert.pem" },
		"key path":           func(_ *InstallPlan, s *config.Spec) { s.ExitCertPaths.KeyFile = "/tmp/key.pem" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			p, raw, node := managedTunnelProjectionFixture(t, config.RoleExit)
			var spec config.Spec
			_ = json.Unmarshal(raw, &spec)
			change(p, &spec)
			raw, _ = json.Marshal(spec)
			got, err := ProjectLocalManagedTunnelRuntime(p, raw, config.RoleExit, node)
			if err == nil || got != nil {
				t.Fatal("unproven preservation accepted")
			}
		})
	}
}

func TestOrdinaryRuntimeProjectionRejectsImplicitManagedDowngrade(t *testing.T) {
	p, raw, node := managedTunnelProjectionFixture(t, config.RoleExit)
	p.Features.MainExitDomain = ""
	if got, err := ProjectLocalRuntime(p, raw, config.RoleExit, node); err == nil || got != nil {
		t.Fatal("omitted managed domain silently downgraded installed ACME TLS")
	}
}
