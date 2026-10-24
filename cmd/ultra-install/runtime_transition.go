package main

import (
	"encoding/json"
	"net"
	"os"
	"reflect"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

type runtimeTransitionPlan struct {
	BotService     bool                                `json:"bot_service"`
	BotEnabled     bool                                `json:"bot_enabled"`
	Role           config.Role                         `json:"role"`
	Classes        []installplan.RuntimeTransitionKind `json:"classes"`
	Ports          []int                               `json:"ports"`
	Source         string                              `json:"source,omitempty"`
	Admin          string                              `json:"admin,omitempty"`
	TLS            bool                                `json:"tls"`
	TLSName        string                              `json:"tls_name,omitempty"`
	TLSProvision   config.TunnelTLSProvision           `json:"tls_provision,omitempty"`
	CertificatePin string                              `json:"certificate_pin,omitempty"`
	WARP           bool                                `json:"warp"`
	WARPPort       int                                 `json:"warp_port,omitempty"`
}

func buildRuntimeTransitionPlan(
	in runtimeProbeInput,
	raw []byte,
	kinds []installplan.RuntimeTransitionKind,
	beforeRaw ...[]byte,
) (*runtimeTransitionPlan, error) {
	var spec config.Spec
	if json.Unmarshal(raw, &spec) != nil {
		return nil, runtimeHostError("projection_failed")
	}
	if len(beforeRaw) > 0 {
		var prior config.Spec
		if json.Unmarshal(beforeRaw[0], &prior) != nil {
			return nil, runtimeHostError("projection_failed")
		}
		if (spec.Role == config.RoleExit && prior.VLESSPort != spec.VLESSPort) ||
			(spec.Role == config.RoleBridge && prior.Exit.Port != spec.Exit.Port) {
			// DB-backed routing uses exits.Node.Port, not spec.Exit.Port. An exact
			// bridge-local node-row CAS checkpoint must precede either side's switch.
			return nil, runtimeHostError("tunnel_port_db_checkpoint_required")
		}
	}
	plan := &runtimeTransitionPlan{
		Role:       in.Request.Role,
		Classes:    kinds,
		Ports:      []int{},
		BotService: in.Request.Role == config.RoleBridge,
		BotEnabled: in.Request.BotEnabled,
	}
	for _, kind := range kinds {
		switch kind {
		case installplan.RuntimeTransitionTLS, installplan.RuntimeTransitionTunnel:
			plan.TLS = true
		case installplan.RuntimeTransitionWARP:
			if spec.Role != config.RoleExit {
				return nil, runtimeHostError("unsupported_transition")
			}
			plan.WARP = in.Request.Features.WARP
			if plan.WARP {
				plan.WARPPort = in.Request.Features.WARPPort
			}
		case installplan.RuntimeTransitionListener:
			plan.Ports = append(plan.Ports, spec.VLESSPort)
			if spec.Role == config.RoleExit {
				plan.Source = in.Request.Bridge.Address
			} else {
				plan.Admin = spec.AdminListen
				if plan.Admin == "" {
					plan.Admin = "127.0.0.1:8443"
				}
				host, _, err := net.SplitHostPort(plan.Admin)
				if err != nil || host != "127.0.0.1" {
					return nil, runtimeHostError("admin_listener_exposure_migration_required")
				}
				if spec.AntiCensor != nil && spec.AntiCensor.PublicXHTTPPort > 0 {
					plan.Ports = append(plan.Ports, spec.AntiCensor.PublicXHTTPPort)
				}
				if spec.BotTelegramProxy != nil && spec.BotTelegramProxy.Enabled && spec.BotTelegramProxy.ListenAddress != "" && spec.BotTelegramProxy.ListenAddress != "127.0.0.1" {
					return nil, runtimeHostError("bot_listener_exposure_migration_required")
				}
			}
		default:
			return nil, runtimeHostError("unsupported_transition")
		}
	}
	if plan.TLS {
		plan.TLSName = spec.SplitHTTPTLS.ServerName
		plan.TLSProvision = spec.TunnelTLSProvision
		if spec.Role == config.RoleExit {
			if spec.ExitCertPaths.CertFile != "/etc/ultra-relay/fullchain.pem" ||
				spec.ExitCertPaths.KeyFile != "/etc/ultra-relay/privkey.pem" {
				return nil, runtimeHostError("tls_custom_path_migration_required")
			}
			if in.Request.Proof != nil {
				plan.CertificatePin = in.Request.Proof.CertificatePin
			}
		}
	}
	return plan, nil
}

func (s runtimeHostStore) authorizedRuntimeTransitions(
	in runtimeProbeInput,
	kinds []installplan.RuntimeTransitionKind,
	plan *runtimeTransitionPlan,
) bool {
	if len(kinds) == 0 {
		return true
	}
	path, err := s.journalPath(in.Request.Transaction)
	if err != nil {
		return false
	}
	image, err := s.image(strings.TrimSuffix(path, ".json") + ".effects.json")
	if err != nil || !image.Exists || image.Mode != 0600 || image.UID != uint32(os.Geteuid()) {
		return false
	}
	var binding struct {
		Version int                   `json:"version"`
		Binding string                `json:"binding_sha256"`
		Plan    runtimeTransitionPlan `json:"plan"`
		State   string                `json:"state"`
	}
	bound := in
	bound.Action = ""
	bound.BotActive = false
	if json.Unmarshal(image.Data, &binding) != nil || binding.Version != 1 || binding.Binding != runtimeHostDigest(bound) ||
		(binding.State != "prepared" && binding.State != "applying" && binding.State != "applied" && binding.State != "rolled_back") {
		return false
	}
	if plan == nil || !reflect.DeepEqual(binding.Plan, *plan) {
		return false
	}
	wanted := map[installplan.RuntimeTransitionKind]bool{}
	for _, kind := range binding.Plan.Classes {
		wanted[kind] = true
	}
	for _, kind := range kinds {
		if !wanted[kind] {
			return false
		}
	}
	return true
}
