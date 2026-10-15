package installplan

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/install"
)

func projectionFixture(t *testing.T) (*InstallPlan, RenderOptions) {
	t.Helper()
	_, opts := adoptionRenderFixture()
	values := map[string]string{
		"BRIDGE": "192.0.2.1", "EXIT": "192.0.2.2", "EXIT_DIAL": "exit.example.com",
		"VLESS_PORT": "7443", "TUNNEL_PORT": "9443", "PRESET": "steamlike", "TRANSPORT": "grpc",
		"SPLITHTTP_HOST": "example.com", "SPLITHTTP_PATH": "/installed", "REALITY_DEST": "example.com:443",
		"PUBLIC_HOST": "vpn.example.com", "GENERATE_EXIT_TLS": "false",
	}
	p, err := CanonicalValuesToPlan(values)
	if err != nil {
		t.Fatal(err)
	}
	return p, opts
}

func TestProjectDesiredRuntimeExplicitConfigWins(t *testing.T) {
	p, opts := projectionFixture(t)
	for k, v := range map[string]string{
		"PRESET": "apijson", "TRANSPORT": "splithttp", "SPLITHTTP_HOST": "tunnel.example.net", "SPLITHTTP_PATH": "/desired",
		"REALITY_DEST": "reality.example.net:443", "REALITY_SNI": "sni.example.net",
		"LOG_LEVEL": "debug", "ROUTING_MODE": "ru_direct", "DOMAIN_DIRECT": "example.net,domain:example.org", "GEOSITE_BLOCK_TAGS": "ads,malware",
		"ANTI_CENSOR_PROFILE": "fast", "DOH_DISABLE": "false", "SPLITHTTP_PADDING": "100-2000", "SPLITHTTP_MAX_CHUNK_KB": "32",
		"REALITY_FINGERPRINTS": "firefox,safari", "FRAGMENT_DISABLE": "true", "DISABLE_VLESS_FLOW": "true",
		"WARP_ENABLE": "true", "WARP_PORT": "40012", "BOT_ENABLE": "true", "BOT_DOMAIN": "bot.example.com",
	} {
		p.SourceValues[k] = v
	}
	var err error
	p, err = CanonicalValuesToPlan(p.SourceValues)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(opts.ExistingBridge)
	result, err := ProjectDesiredRuntime(p, opts)
	if err != nil {
		t.Fatal(err)
	}
	b, e := result.DesiredState.BridgeSpecObject, result.DesiredState.ExitSpecObjects["primary"]
	if b.MimicPreset != "apijson" || e.MimicPreset != b.MimicPreset || b.TunnelTransport != config.TunnelTransportSplitHTTP || e.TunnelTransport != b.TunnelTransport {
		t.Fatal("config did not replace installed preset/transport")
	}
	if b.SplithttpPath != "/desired" || e.SplithttpPath != b.SplithttpPath || b.SplithttpHost != "tunnel.example.net" || e.SplithttpHost != b.SplithttpHost || b.SplitHTTPTLS.ServerName != b.SplithttpHost {
		t.Fatal("tunnel peers disagree with desired path/host")
	}
	if b.Reality.Dest != "reality.example.net:443" || !reflect.DeepEqual(b.Reality.ServerNames, []string{"sni.example.net"}) || b.Reality.PrivateKey != opts.ExistingBridge.Reality.PrivateKey || b.Reality.PublicKey != opts.ExistingBridge.Reality.PublicKey {
		t.Fatal("REALITY values or identity incorrect")
	}
	if b.RoutingMode != "ru_direct" || !reflect.DeepEqual(b.DomainDirect, []string{"domain:example.net", "domain:example.org"}) || !reflect.DeepEqual(b.GeositeBlockTags, []string{"ads", "malware"}) || b.VLESSFlow != "none" {
		t.Fatal("routing/flow overlay incorrect")
	}
	if b.AntiCensor.DisableDOH || b.AntiCensor.Profile != "fast" || b.AntiCensor.SplitHTTPPadding != "100-2000" || b.AntiCensor.SplitHTTPMaxChunkKB != 32 || b.AntiCensor.Fragment == nil || b.AntiCensor.Fragment.Packets != "" || !reflect.DeepEqual(b.AntiCensor.RealityFingerprints, []string{"firefox", "safari"}) {
		t.Fatal("anti-censor overlay incorrect")
	}
	if !e.AntiCensor.WARPProxy || e.AntiCensor.WARPProxyPort != 40012 || !result.BotEnabled || !b.BotTelegramProxy.Enabled || b.BotTelegramProxy.Port != 10819 {
		t.Fatal("WARP/bot overlay incorrect")
	}
	if result.DesiredState.BridgeEnv != "ULTRA_RELAY_ADMIN_TOKEN=fixture-admin\nULTRA_RELAY_LOG_LEVEL=debug\n"+databaseEnvForFixture(opts) || result.DesiredState.ExitEnvs["primary"] != "ULTRA_RELAY_LOG_LEVEL=debug\n" {
		t.Fatal("desired environment mismatch")
	}
	if len(result.Transitions) == 0 || !reflect.DeepEqual(result.CoordinatedNodes, []string{"primary"}) {
		t.Fatal("missing choreography requirements")
	}
	after, _ := json.Marshal(opts.ExistingBridge)
	if string(before) != string(after) || p.Bridge.AdminListen != "127.0.0.1:8443" { // canonical parser initializes AdminListen itself.
		t.Fatal("projection mutated inspected inputs")
	}
	if !reflect.DeepEqual(b.Exit, opts.ExistingBridge.Exit) || b.Database.DSN != opts.ExistingBridge.Database.DSN || e.Exit.TunnelUUID != opts.ExistingExits["primary"].Exit.TunnelUUID || !reflect.DeepEqual(result.DesiredState.Bootstrap, opts.PriorBootstrap) {
		t.Fatal("projection changed identity or topology")
	}
}

func databaseEnvForFixture(opts RenderOptions) string {
	// Use the pre-existing renderer's escaping contract instead of embedding DSN quoting.
	return install.FormatDBEnvLine(opts.ExistingBridge.Database.DSN)
}

func TestProjectDesiredRuntimeRemovedOptionalsReset(t *testing.T) {
	p, opts := projectionFixture(t)
	opts.ExistingBridge.RoutingMode = config.RoutingModeRUDirect
	opts.ExistingBridge.DomainDirect = []string{"domain:stale.example.com"}
	opts.ExistingBridge.GeositeBlockTags = []string{"stale"}
	opts.ExistingBridge.AntiCensor.Fragment = &config.FragmentSpec{Packets: "tlshello", Length: "20-30"}
	opts.ExistingBridge.AntiCensor.PublicXHTTPPort = 9444
	opts.ExistingBridge.AntiCensor.RealityFingerprints = []string{"firefox"}
	opts.ExistingBridge.Reality.ServerNames = []string{"stale.example.com"}
	opts.ExistingBridgeJSON, _ = json.Marshal(opts.ExistingBridge)
	for _, k := range []string{"PRESET", "TRANSPORT", "SPLITHTTP_HOST", "SPLITHTTP_PATH"} {
		delete(p.SourceValues, k)
	}
	var err error
	p, err = CanonicalValuesToPlan(p.SourceValues)
	if err != nil {
		t.Fatal(err)
	}
	result, err := ProjectDesiredRuntime(p, opts)
	if err != nil {
		t.Fatal(err)
	}
	b, e := result.DesiredState.BridgeSpecObject, result.DesiredState.ExitSpecObjects["primary"]
	if b.MimicPreset != "apijson" || b.TunnelTransport != config.TunnelTransportSplitHTTP || b.SplithttpPath != "" || b.SplithttpHost != "" || e.SplithttpPath != "" || e.SplithttpHost != "" {
		t.Fatal("removed tunnel overrides retained")
	}
	if b.RoutingMode != "" || len(b.DomainDirect) != 0 || len(b.GeositeBlockTags) != 0 || b.AntiCensor.Profile != "" || b.AntiCensor.DisableDOH || b.AntiCensor.Fragment != nil || b.AntiCensor.PublicXHTTPPort != 0 || len(b.AntiCensor.RealityFingerprints) != 0 || b.AntiCensor.SplitHTTPPadding != "" || b.AntiCensor.SplitHTTPMaxChunkKB != 0 {
		t.Fatal("removed optional overrides retained")
	}
	if b.Reality.Dest != "example.com:443" || !reflect.DeepEqual(b.Reality.ServerNames, []string{"example.com"}) {
		t.Fatal("missing SNI did not return to destination default")
	}
	if e.AntiCensor.WARPProxy || e.AntiCensor.WARPProxyPort != 0 || result.BotEnabled || b.BotTelegramProxy.Enabled || b.BotTelegramProxy.Port != 10819 {
		t.Fatal("removed enable flags did not disable services or lost unmanaged proxy port")
	}
	if b.VLESSFlow != config.DefaultVLESSFlow {
		t.Fatal("missing flow did not reset default")
	}
}

func TestProjectDesiredRuntimeRequiresRealityDestinationWhenOmitted(t *testing.T) {
	p, opts := projectionFixture(t)
	delete(p.SourceValues, "REALITY_DEST")
	p, err := CanonicalValuesToPlan(p.SourceValues)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ProjectDesiredRuntime(p, opts); err == nil || !strings.Contains(err.Error(), "REALITY_DEST") {
		t.Fatalf("omitted REALITY_DEST must fail without a safe default, got %v", err)
	}
}

func TestProjectDesiredRuntimePreservesUnknownNestedAndDynamicState(t *testing.T) {
	p, opts := projectionFixture(t)
	raw, _ := runtimeDocument(opts.ExistingBridgeJSON)
	runtimeSet(raw, "future_top_level", map[string]any{"enabled": true})
	for _, key := range []string{"anti_censor", "reality", "splithttp_tls", "bot_telegram_proxy"} {
		obj := runtimeObject(raw, key)
		runtimeSet(obj, "future_field", []int{1, 2})
		runtimeSet(raw, key, obj)
	}
	anti := runtimeObject(raw, "anti_censor")
	runtimeSet(anti, "grpc_initial_window_size", 123456)
	runtimeSet(anti, "warp_direct_domains", []string{"unmanaged.example.com"})
	runtimeSet(raw, "anti_censor", anti)
	opts.ExistingBridgeJSON, _ = json.Marshal(raw)
	if err := json.Unmarshal(opts.ExistingBridgeJSON, opts.ExistingBridge); err != nil {
		t.Fatal(err)
	}
	dynamic := exits.BootstrapEntry{Name: "dynamic", Address: "dynamic.example.com", Port: 9443, TunnelUUID: "22222222-2222-2222-2222-222222222222", Priority: 75}
	opts.PriorBootstrap = append(opts.PriorBootstrap, dynamic)
	opts.ExistingBridge.Exit = config.ExitTunnelSpec{Address: dynamic.Address, Port: dynamic.Port, TunnelUUID: dynamic.TunnelUUID, PinnedPeerCertSHA256: "dynamic-pin"}
	runtimeSet(raw, "exit", opts.ExistingBridge.Exit)
	opts.ExistingBridgeJSON, _ = json.Marshal(raw)
	result, err := ProjectDesiredRuntime(p, opts)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := runtimeDocument(result.DesiredState.BridgeSpec)
	if !equalJSONValue(out["future_top_level"], raw["future_top_level"]) {
		t.Fatal("unmanaged top-level value lost")
	}
	for _, key := range []string{"anti_censor", "reality", "splithttp_tls", "bot_telegram_proxy"} {
		before, after := runtimeObject(raw, key), runtimeObject(out, key)
		if !equalJSONValue(before["future_field"], after["future_field"]) {
			t.Fatalf("unknown %s field lost", key)
		}
	}
	if result.DesiredState.BridgeSpecObject.AntiCensor.GRPCInitialWindowSize != 123456 || !reflect.DeepEqual(result.DesiredState.BridgeSpecObject.AntiCensor.WARPDirectDomains, []string{"unmanaged.example.com"}) || result.DesiredState.BridgeSpecObject.Exit != opts.ExistingBridge.Exit || !reflect.DeepEqual(result.DesiredState.Bootstrap, opts.PriorBootstrap) {
		t.Fatal("unmanaged tuning or dynamic topology changed")
	}
	if !reflect.DeepEqual(result.CoordinatedNodes, []string{"dynamic", "primary"}) {
		t.Fatal("dynamic node omitted from coordination")
	}
}

func TestProjectDesiredRuntimeRejectsMissingPresenceAndUnprovedSnapshot(t *testing.T) {
	p, opts := projectionFixture(t)
	p.SourceValues = nil
	if _, err := ProjectDesiredRuntime(p, opts); err == nil {
		t.Fatal("accepted plan without presence")
	}
	p, opts = projectionFixture(t)
	opts.ExistingBridgeJSON = nil
	if _, err := ProjectDesiredRuntime(p, opts); err == nil {
		t.Fatal("accepted snapshot without original JSON")
	}
	p, opts = projectionFixture(t)
	opts.ExistingBridge.Exit.TunnelUUID = "changed"
	if _, err := ProjectDesiredRuntime(p, opts); err == nil {
		t.Fatal("accepted inconsistent identity")
	}
}

func equalJSONValue(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

func TestProjectDesiredRuntimeCoordinatesSameNodePortChange(t *testing.T) {
	p, opts := projectionFixture(t)
	p.Exits[0].Port = 10443
	p.Bridge.TunnelPort = 10443
	p.SourceValues["TUNNEL_PORT"] = "10443"
	beforePlan, _ := json.Marshal(p)
	beforeBridge := append([]byte(nil), opts.ExistingBridgeJSON...)
	beforeExit := append([]byte(nil), opts.ExistingExitJSON["primary"]...)
	result, err := ProjectDesiredRuntime(p, opts)
	if err != nil {
		t.Fatal(err)
	}
	ds := result.DesiredState
	if ds.BridgeSpecObject.Exit.Port != 10443 || ds.ExitSpecObjects["primary"].VLESSPort != 10443 || ds.Bootstrap[0].Port != 10443 {
		t.Fatal("same-node listener change not projected to all peers")
	}
	if ds.BridgeSpecObject.Exit.TunnelUUID != opts.ExistingBridge.Exit.TunnelUUID || ds.BridgeSpecObject.Exit.PinnedPeerCertSHA256 != opts.ExistingBridge.Exit.PinnedPeerCertSHA256 || ds.Bootstrap[0].PinnedPeerCertSHA256 != opts.PriorBootstrap[0].PinnedPeerCertSHA256 {
		t.Fatal("port change rotated identity or pin")
	}
	tunnel, listener := false, false
	for _, transition := range result.Transitions {
		for _, field := range transition.Fields {
			if field == "TUNNEL_PORT" {
				tunnel = tunnel || transition.Kind == RuntimeTransitionTunnel
				listener = listener || transition.Kind == RuntimeTransitionListener
			}
		}
	}
	if !tunnel || !listener {
		t.Fatal("port change omitted transition requirements")
	}
	afterPlan, _ := json.Marshal(p)
	if string(beforePlan) != string(afterPlan) || string(beforeBridge) != string(opts.ExistingBridgeJSON) || string(beforeExit) != string(opts.ExistingExitJSON["primary"]) || opts.PriorBootstrap[0].Port != 9443 {
		t.Fatal("projection mutated input snapshot")
	}
}

func TestProjectLocalRuntimeMatchesFleetProjection(t *testing.T) {
	p, opts := projectionFixture(t)
	p.Features.Preset = "apijson"
	p.Features.WARP = true
	p.Features.WARPPort = 40015
	p.Features.SplitHTTPPath = "/local-desired"
	p.Exits[0].Port = 10443
	fleet, err := ProjectDesiredRuntime(p, opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		role      config.Role
		node      string
		raw, want []byte
	}{
		{config.RoleBridge, "", opts.ExistingBridgeJSON, fleet.DesiredState.BridgeSpec},
		{config.RoleExit, "primary", opts.ExistingExitJSON["primary"], fleet.DesiredState.ExitSpecs["primary"]},
	} {
		t.Run(string(tc.role), func(t *testing.T) {
			input := append([]byte(nil), tc.raw...)
			local, err := ProjectLocalRuntime(p, tc.raw, tc.role, tc.node)
			if err != nil {
				t.Fatal(err)
			}
			if !equalJSONValue(local.SpecJSON, tc.want) {
				t.Fatal("local and fleet projection differ")
			}
			if string(input) != string(tc.raw) {
				t.Fatal("local projection mutated source")
			}
			for _, transition := range local.Transitions {
				if transition.Node != "bridge" && transition.Node != "primary" {
					t.Fatal("local projection returned foreign node metadata")
				}
			}
		})
	}
}

func TestProjectLocalRuntimeResetsAbsentOptionalsAndPreservesSecrets(t *testing.T) {
	p, opts := projectionFixture(t)
	delete(p.SourceValues, "SPLITHTTP_HOST")
	delete(p.SourceValues, "SPLITHTTP_PATH")
	var err error
	p, err = CanonicalValuesToPlan(p.SourceValues)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		role config.Role
		node string
		raw  []byte
	}{
		{config.RoleBridge, "", opts.ExistingBridgeJSON},
		{config.RoleExit, "primary", opts.ExistingExitJSON["primary"]},
	} {
		t.Run(string(tc.role), func(t *testing.T) {
			source, _ := runtimeDocument(tc.raw)
			runtimeSet(source, "future_private", map[string]any{"password": "fixture-private-sentinel", "enabled": true})
			anti := runtimeObject(source, "anti_censor")
			runtimeSet(anti, "future_anti", map[string]any{"secret": "fixture-anti-sentinel"})
			runtimeSet(source, "anti_censor", anti)
			raw, _ := json.Marshal(source)
			local, err := ProjectLocalRuntime(p, raw, tc.role, tc.node)
			if err != nil {
				t.Fatal(err)
			}
			projected, _ := runtimeDocument(local.SpecJSON)
			if !equalJSONValue(source["future_private"], projected["future_private"]) || !equalJSONValue(anti["future_anti"], runtimeObject(projected, "anti_censor")["future_anti"]) {
				t.Fatal("unknown credential field lost")
			}
			var spec config.Spec
			if err = json.Unmarshal(local.SpecJSON, &spec); err != nil {
				t.Fatal(err)
			}
			if spec.SplithttpHost != "" || spec.SplithttpPath != "" || spec.AntiCensor.Profile != "" || spec.AntiCensor.DisableDOH || spec.AntiCensor.SplitHTTPPadding != "" || spec.AntiCensor.SplitHTTPMaxChunkKB != 0 {
				t.Fatal("removed overrides did not reset")
			}
			if tc.role == config.RoleBridge {
				if spec.BotTelegramProxy.Enabled || spec.Reality.PrivateKey != opts.ExistingBridge.Reality.PrivateKey || spec.Database.DSN != opts.ExistingBridge.Database.DSN || spec.Exit != opts.ExistingBridge.Exit {
					t.Fatal("bridge secrets changed or bot flag did not reset")
				}
			} else if spec.AntiCensor.WARPProxy || spec.AntiCensor.WARPProxyPort != 0 || spec.Exit.TunnelUUID != opts.ExistingExits["primary"].Exit.TunnelUUID || spec.ExitCertPaths != opts.ExistingExits["primary"].ExitCertPaths {
				t.Fatal("exit secrets changed or WARP did not reset")
			}
			exported, err := json.Marshal(local)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"fixture-private-sentinel", "fixture-anti-sentinel", "fixture-private", "fixture-public", "postgres://"} {
				if bytes.Contains(exported, []byte(secret)) {
					t.Fatal("host-local raw candidate leaked through JSON result")
				}
			}
		})
	}
}

func TestProjectLocalRuntimeRejectsInvalidInputWithoutSecrets(t *testing.T) {
	p, opts := projectionFixture(t)
	for _, tc := range []struct {
		name string
		role config.Role
		node string
		raw  []byte
	}{
		{"malformed", config.RoleBridge, "", []byte(`{"secret":"fixture-private-sentinel"`)},
		{"wrong field type", config.RoleBridge, "", []byte(`{"role":"bridge","vless_port":"fixture-private-sentinel"}`)},
		{"invalid spec", config.RoleBridge, "", []byte(`{"role":"bridge","reality":{"private_key":"fixture-private-sentinel"}}`)},
		{"wrong role", config.RoleExit, "primary", opts.ExistingBridgeJSON},
		{"unsupported role", config.Role("unknown"), "", opts.ExistingBridgeJSON},
		{"unknown exit", config.RoleExit, "unknown", opts.ExistingExitJSON["primary"]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ProjectLocalRuntime(p, tc.raw, tc.role, tc.node)
			if err == nil || result != nil {
				t.Fatal("invalid input accepted")
			}
			if strings.Contains(err.Error(), "fixture-private-sentinel") {
				t.Fatal("error leaked raw credentials")
			}
		})
	}
	p.SourceValues = nil
	if _, err := ProjectLocalRuntime(p, opts.ExistingBridgeJSON, config.RoleBridge, ""); err == nil {
		t.Fatal("missing presence accepted")
	}
}

func TestProjectLocalRuntimeDynamicExitPreservesListenerAndIdentity(t *testing.T) {
	p, opts := projectionFixture(t)
	p.Features.Preset = "apijson"
	p.Features.Transport = "splithttp"
	p.Features.WARP = true
	p.Features.WARPPort = 40025
	dynamic := *opts.ExistingExits["primary"]
	dynamic.VLESSPort = 11443
	dynamic.Exit = config.ExitTunnelSpec{Address: "dynamic.example.net", Port: 12443, TunnelUUID: "22222222-2222-2222-2222-222222222222", PinnedPeerCertSHA256: "dynamic-pin"}
	raw, _ := json.Marshal(dynamic)
	result, err := ProjectLocalRuntime(p, raw, config.RoleExit, "")
	if err != nil {
		t.Fatal(err)
	}
	var projected config.Spec
	if err = json.Unmarshal(result.SpecJSON, &projected); err != nil {
		t.Fatal(err)
	}
	if projected.VLESSPort != dynamic.VLESSPort || projected.Exit != dynamic.Exit || projected.ExitCertPaths != dynamic.ExitCertPaths {
		t.Fatal("dynamic listener or identity changed")
	}
	if projected.MimicPreset != "apijson" || projected.TunnelTransport != config.TunnelTransportSplitHTTP || !projected.AntiCensor.WARPProxy || projected.AntiCensor.WARPProxyPort != 40025 {
		t.Fatal("dynamic feature overlay missing")
	}
	for _, transition := range result.Transitions {
		for _, field := range transition.Fields {
			if field == "TUNNEL_PORT" {
				t.Fatal("dynamic listener received static port transition")
			}
		}
	}
	// The bridge's active dynamic route is independently projected and retains
	// its endpoint even when the static fleet's desired tunnel port differs.
	bridge := *opts.ExistingBridge
	bridge.Exit = dynamic.Exit
	bridgeRaw, _ := json.Marshal(bridge)
	localBridge, err := ProjectLocalRuntime(p, bridgeRaw, config.RoleBridge, "")
	if err != nil {
		t.Fatal(err)
	}
	var projectedBridge config.Spec
	if err = json.Unmarshal(localBridge.SpecJSON, &projectedBridge); err != nil {
		t.Fatal(err)
	}
	if projectedBridge.Exit != dynamic.Exit {
		t.Fatal("active dynamic bridge route changed")
	}
}
