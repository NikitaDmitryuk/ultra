package installplan

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/install"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
)

// RuntimeTransitionKind identifies the deployment choreography needed to apply a
// projection. These are maintenance operations within a fleet, not migrations.
type RuntimeTransitionKind string

const (
	RuntimeTransitionTunnel   RuntimeTransitionKind = "coordinated_tunnel"
	RuntimeTransitionListener RuntimeTransitionKind = "listener"
	RuntimeTransitionWARP     RuntimeTransitionKind = "warp_service"
	RuntimeTransitionTLS      RuntimeTransitionKind = "tunnel_tls_provision"
)

type RuntimeTransition struct {
	Kind   RuntimeTransitionKind
	Node   string
	Fields []string
}

type RuntimeProjection struct {
	DesiredState *DesiredState
	BotEnabled   bool
	Transitions  []RuntimeTransition
	// CoordinatedNodes includes dynamic exits whose spec is not in ExistingExits.
	// The executor must inspect and coordinate those nodes before tunnel activation.
	CoordinatedNodes []string
}

// ProjectDesiredRuntime overlays config-owned values onto an inspected runtime.
// It does not generate credentials, perform I/O or mutate its inputs. Callers
// must separately prove unchanged bridge/node membership and database identity
// against the prior deployment plan before any mutation: specs alone cannot
// establish SSH hosts, database replicas, or the static/dynamic ownership split.
// SourceValues must be present so omission can reset optionals deliberately.
func ProjectDesiredRuntime(p *InstallPlan, opts RenderOptions) (*RuntimeProjection, error) {
	if p == nil || p.SourceValues == nil {
		return nil, fmt.Errorf("desired runtime projection requires canonical config presence")
	}
	desired, err := validatedRuntimePlan(p, false)
	if err != nil {
		return nil, err
	}
	p = desired
	// Reuse the adoption proof for route identity and raw/spec correspondence.
	// Adoption's certificate path restriction is kept: the deployment executor
	// currently manages those exact paths and must not rewrite arbitrary files.
	opts.PreserveRuntime = true
	proofPlan := *p
	proofPlan.Exits = append([]ExitNode(nil), p.Exits...)
	desiredPorts := make(map[string]int, len(p.Exits))
	for i, ex := range p.Exits {
		desiredPorts[ex.Name] = ex.Port
		found := false
		for _, entry := range opts.PriorBootstrap {
			if entry.Name == ex.Name && entry.Address == ex.DialAddr {
				proofPlan.Exits[i].Port = entry.Port
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("desired runtime static exit identity differs from inspected topology")
		}
	}
	ds, err := renderPreservedRuntime(&proofPlan, opts)
	if err != nil {
		return nil, err
	}
	result := &RuntimeProjection{DesiredState: ds, BotEnabled: p.Bot.Enabled}
	bridgeExitPort := ds.BridgeSpecObject.Exit.Port
	for i, entry := range ds.Bootstrap {
		if port, ok := desiredPorts[entry.Name]; ok {
			ds.Bootstrap[i].Port = port
			if entry.Address == ds.BridgeSpecObject.Exit.Address && entry.Port == ds.BridgeSpecObject.Exit.Port && entry.TunnelUUID == ds.BridgeSpecObject.Exit.TunnelUUID {
				bridgeExitPort = port
			}
		}
	}
	var transitions []RuntimeTransition
	ds.BridgeSpec, ds.BridgeSpecObject, transitions, err = projectRuntimeSpec(p, "bridge", ds.BridgeSpec, ds.BridgeSpecObject, false, 0, bridgeExitPort)
	result.Transitions = append(result.Transitions, transitions...)
	if err != nil {
		return nil, err
	}
	for _, ex := range p.Exits {
		ds.ExitSpecs[ex.Name], ds.ExitSpecObjects[ex.Name], transitions, err = projectRuntimeSpec(p, ex.Name, ds.ExitSpecs[ex.Name], ds.ExitSpecObjects[ex.Name], true, desiredPorts[ex.Name], 0)
		result.Transitions = append(result.Transitions, transitions...)
		if err != nil {
			return nil, err
		}
		ds.ExitEnvs[ex.Name] = fmt.Sprintf("ULTRA_RELAY_LOG_LEVEL=%s\n", p.Features.LogLevel)
	}
	ds.BridgeEnv = fmt.Sprintf("ULTRA_RELAY_ADMIN_TOKEN=%s\nULTRA_RELAY_LOG_LEVEL=%s\n", ds.AdminToken, p.Features.LogLevel)
	if ds.DBDSN != "" {
		ds.BridgeEnv += install.FormatDBEnvLine(ds.DBDSN)
	}
	ds.SplitHTTPHost, ds.SplitHTTPPath = strings.TrimSpace(p.Features.SplitHTTPHost), strings.TrimSpace(p.Features.SplitHTTPPath)
	for _, t := range result.Transitions {
		if t.Kind == RuntimeTransitionTunnel {
			for _, entry := range ds.Bootstrap {
				result.CoordinatedNodes = append(result.CoordinatedNodes, entry.Name)
			}
			sort.Strings(result.CoordinatedNodes)
			break
		}
	}
	return result, nil
}

func runtimeDocument(raw []byte) (map[string]json.RawMessage, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, fmt.Errorf("runtime specification must be an object")
	}
	return doc, nil
}

func runtimeObject(doc map[string]json.RawMessage, key string) map[string]json.RawMessage {
	var obj map[string]json.RawMessage
	_ = json.Unmarshal(doc[key], &obj)
	if obj == nil {
		obj = make(map[string]json.RawMessage)
	}
	return obj
}

func runtimeSet(doc map[string]json.RawMessage, key string, value any) {
	// Values originate only in typed plan fields / JSON objects, which are always
	// marshalable. Keeping explicit zeros makes resets visible in the artifact.
	doc[key], _ = json.Marshal(value)
}

func validatedRuntimePlan(p *InstallPlan, local bool) (*InstallPlan, error) {
	if p == nil || p.SourceValues == nil {
		return nil, fmt.Errorf("desired runtime projection requires canonical config presence")
	}
	// Validate a copy: ValidatePlan fills defaults and must not mutate the input.
	planJSON, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	var desired InstallPlan
	if err = json.Unmarshal(planJSON, &desired); err != nil {
		return nil, err
	}
	desired.SourceValues = p.SourceValues
	desired.ControllerLocalTarget = p.ControllerLocalTarget
	desired.ControllerLocal = p.ControllerLocal
	if local && desired.SchemaVersion == 1 {
		// Local probe/prepare requests are versioned independently of external
		// installation plans and intentionally omit fleet/automation policy.
		err = validatePlan(&desired, true)
	} else {
		err = ValidatePlan(&desired)
	}
	if err != nil {
		return nil, err
	}
	return &desired, nil
}

// ValidateLocalRuntimePlan validates the private, host-local schema 1 request
// envelope. It cannot be used as a deployment plan or bypass schema 2 policy.
func ValidateLocalRuntimePlan(p *InstallPlan) error {
	_, err := validatedRuntimePlan(p, true)
	return err
}

// LocalRuntimeProjection is an in-process host-local candidate. SpecJSON retains
// credentials and must never be emitted into logs, receipts or remote results.
// Only Transitions is suitable for reporting outside the target host.
type LocalRuntimeProjection struct {
	SpecJSON    []byte              `json:"-"`
	Transitions []RuntimeTransition `json:"transitions,omitempty"`
}

// ProjectLocalRuntime overlays one target's inspected spec without needing any
// peer specs, environment secrets or bootstrap receipts. For exit, nodeName must
// identify a static exit in the canonical plan, or be empty for a live dynamic
// exit whose listener and identity are preserved. Bridge may use an empty name.
// The caller must verify node/database identity and coordinate Transitions before
// activating the candidate; this pure function does not authorize deployment.
func ProjectLocalRuntime(p *InstallPlan, raw []byte, role config.Role, nodeName string) (*LocalRuntimeProjection, error) {
	p, err := validatedRuntimePlan(p, true)
	if err != nil {
		return nil, err
	}
	if role != config.RoleBridge && role != config.RoleExit {
		return nil, fmt.Errorf("local runtime projection requires bridge or exit role")
	}
	if _, err := runtimeDocument(raw); err != nil {
		return nil, fmt.Errorf("invalid local runtime JSON")
	}
	var previous, checked config.Spec
	if json.Unmarshal(raw, &previous) != nil || json.Unmarshal(raw, &checked) != nil {
		return nil, fmt.Errorf("invalid local runtime specification")
	}
	if previous.Role != role {
		return nil, fmt.Errorf("local runtime specification role mismatch")
	}
	if checked.Validate() != nil {
		return nil, fmt.Errorf("invalid local runtime specification")
	}
	exitPort, bridgePort := 0, previous.Exit.Port
	if role == config.RoleExit && nodeName == "" {
		exitPort = previous.VLESSPort
	} else if role == config.RoleExit {
		found := false
		for _, ex := range p.Exits {
			if ex.Name == nodeName {
				if ex.TunnelUUID != "" && ex.TunnelUUID != previous.Exit.TunnelUUID {
					return nil, fmt.Errorf("local exit identity mismatch")
				}
				exitPort, found = ex.Port, true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("local exit is absent from canonical plan")
		}
	} else {
		nodeName = "bridge"
		for _, ex := range p.Exits {
			if ex.DialAddr == previous.Exit.Address {
				if ex.TunnelUUID != "" && ex.TunnelUUID != previous.Exit.TunnelUUID {
					return nil, fmt.Errorf("local bridge tunnel identity mismatch")
				}
				bridgePort = ex.Port
				break
			}
		}
	}
	candidate, _, transitions, err := projectRuntimeSpec(p, nodeName, raw, &previous, role == config.RoleExit, exitPort, bridgePort)
	if err != nil {
		// Validation may mention caller-supplied fields; expose a fixed error here
		// rather than carrying any raw spec or secret-bearing decoder details.
		return nil, fmt.Errorf("invalid desired local runtime specification")
	}
	return &LocalRuntimeProjection{SpecJSON: candidate, Transitions: transitions}, nil
}

func projectRuntimeSpec(p *InstallPlan, node string, raw []byte, previous *config.Spec, exit bool, exitPort, bridgeExitPort int) ([]byte, *config.Spec, []RuntimeTransition, error) {
	var transitions []RuntimeTransition
	strat, err := mimic.New(p.Features.Preset)
	if err != nil {
		return nil, nil, nil, err
	}
	host := strings.TrimSpace(p.Features.SplitHTTPHost)
	effectiveHost := host
	if effectiveHost == "" {
		effectiveHost = strat.Host()
	}
	splitPath := strings.TrimSpace(p.Features.SplitHTTPPath)
	doc, err := runtimeDocument(raw)
	if err != nil {
		return nil, nil, nil, err
	}
	owned := map[string]any{
		"mimic_preset": strat.Name(), "tunnel_transport": p.Features.Transport,
		"splithttp_host": host, "splithttp_path": splitPath,
	}
	tls := runtimeObject(doc, "splithttp_tls")
	runtimeSet(tls, "server_name", effectiveHost)
	owned["splithttp_tls"] = tls
	provision := config.TunnelTLSUserProv
	if p.Features.GenerateExitTLS {
		provision = config.TunnelTLSSelfSigned
	}
	owned["tunnel_tls_provision"] = provision
	anti := runtimeObject(doc, "anti_censor")
	for key, value := range map[string]any{
		"profile": p.Features.AntiCensorProfile, "disable_doh": p.Features.DisableDOH,
		"splithttp_padding":      p.Features.SplitHTTPPadding,
		"splithttp_max_chunk_kb": p.Features.SplitHTTPMaxChunkKB,
	} {
		runtimeSet(anti, key, value)
	}
	if exit {
		owned["vless_port"] = exitPort
		runtimeSet(anti, "warp_proxy", p.Features.WARP)
		// Zero means the runtime's default port when disabled; clear stale tuning.
		port := 0
		if p.Features.WARP {
			port = p.Features.WARPPort
		}
		runtimeSet(anti, "warp_proxy_port", port)
	} else {
		runtimeSet(anti, "public_xhttp_port", p.Features.PublicXHTTPPort)
		runtimeSet(anti, "reality_fingerprints", splitComma(p.Features.RealityFingerprintsCSV))
		// Preserve unknown nested settings only when the fragment block exists.
		// Omission returns to nil (disabled) instead of retaining old packets.
		if p.Features.DisableFragment {
			runtimeSet(anti, "fragment", map[string]any{"packets": ""})
		} else {
			delete(anti, "fragment")
		}
		owned["routing_mode"] = p.Features.RoutingMode
		owned["geosite_block_tags"] = splitComma(p.Features.GeositeBlockTags)
		owned["domain_direct"] = normalizeDomains(splitComma(p.Features.DomainDirect))
		owned["vless_port"] = p.Bridge.VLESSPort
		route := runtimeObject(doc, "exit")
		runtimeSet(route, "port", bridgeExitPort)
		owned["exit"] = route
		owned["admin_listen"] = p.Bridge.AdminListen
		flow := p.Features.VLESSFlow
		if p.Features.DisableVLESSFlow {
			flow = "none"
		}
		owned["vless_flow"] = flow
		reality := runtimeObject(doc, "reality")
		dest := strings.TrimSpace(p.Bridge.RealityDest)
		if dest == "" {
			return nil, nil, nil, fmt.Errorf("desired REALITY_DEST is required; no safe default exists")
		}
		if _, _, err := net.SplitHostPort(dest); err != nil {
			return nil, nil, nil, fmt.Errorf("desired REALITY_DEST must be host:port")
		}
		sni := strings.TrimSpace(p.Bridge.RealitySNI)
		if sni == "" {
			sni, _, _ = net.SplitHostPort(dest)
		}
		runtimeSet(reality, "dest", dest)
		runtimeSet(reality, "server_names", []string{sni})
		owned["reality"] = reality
		bot := runtimeObject(doc, "bot_telegram_proxy")
		runtimeSet(bot, "enabled", p.Bot.Enabled || p.Features.BotTelegramProxy)
		owned["bot_telegram_proxy"] = bot
	}
	owned["anti_censor"] = anti
	for key, value := range owned {
		runtimeSet(doc, key, value)
	}
	projected, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, nil, nil, err
	}
	var spec, checked config.Spec
	if err = json.Unmarshal(projected, &spec); err != nil {
		return nil, nil, nil, err
	}
	if err = json.Unmarshal(projected, &checked); err != nil {
		return nil, nil, nil, err
	}
	if err = checked.Validate(); err != nil {
		return nil, nil, nil, fmt.Errorf("desired runtime %s: %w", node, err)
	}
	appendTransition := func(kind RuntimeTransitionKind, fields ...string) {
		if len(fields) != 0 {
			transitions = append(transitions, RuntimeTransition{Kind: kind, Node: node, Fields: fields})
		}
	}
	var tunnel []string
	for _, f := range []struct {
		name          string
		before, after any
	}{
		{"PRESET", previous.MimicPreset, spec.MimicPreset},
		{"TRANSPORT", previous.TunnelTransport, spec.TunnelTransport},
		{"SPLITHTTP_HOST", previous.SplithttpHost, spec.SplithttpHost},
		{"SPLITHTTP_PATH", previous.SplithttpPath, spec.SplithttpPath},
		{"SPLITHTTP_TLS_SERVER_NAME", previous.SplitHTTPTLS.ServerName, spec.SplitHTTPTLS.ServerName},
		{"TUNNEL_PORT", previous.Exit.Port, spec.Exit.Port},
	} {
		if !reflect.DeepEqual(f.before, f.after) {
			tunnel = append(tunnel, f.name)
		}
	}
	appendTransition(RuntimeTransitionTunnel, tunnel...)
	if previous.TunnelTLSProvision != spec.TunnelTLSProvision {
		appendTransition(RuntimeTransitionTLS, "GENERATE_EXIT_TLS")
	}
	if previous.VLESSPort != spec.VLESSPort {
		if exit {
			appendTransition(RuntimeTransitionTunnel, "TUNNEL_PORT")
			appendTransition(RuntimeTransitionListener, "TUNNEL_PORT")
		} else {
			appendTransition(RuntimeTransitionListener, "VLESS_PORT")
		}
	}
	if !exit {
		if previous.AdminListen != spec.AdminListen {
			appendTransition(RuntimeTransitionListener, "ADMIN_LISTEN")
		}
		priorPort := 0
		if previous.AntiCensor != nil {
			priorPort = previous.AntiCensor.PublicXHTTPPort
		}
		if priorPort != p.Features.PublicXHTTPPort {
			appendTransition(RuntimeTransitionListener, "PUBLIC_XHTTP_PORT")
		}
		priorBot := previous.BotTelegramProxy != nil && previous.BotTelegramProxy.Enabled
		if priorBot != spec.BotTelegramProxy.Enabled {
			appendTransition(RuntimeTransitionListener, "BOT_ENABLE")
		}
	} else {
		oldEnabled, oldPort := false, 0
		if previous.AntiCensor != nil {
			oldEnabled, oldPort = previous.AntiCensor.WARPProxy, previous.AntiCensor.WARPProxyPort
		}
		if oldEnabled != spec.AntiCensor.WARPProxy || oldPort != spec.AntiCensor.WARPProxyPort {
			appendTransition(RuntimeTransitionWARP, "WARP_ENABLE", "WARP_PORT")
		}
	}
	return projected, &spec, transitions, nil
}
