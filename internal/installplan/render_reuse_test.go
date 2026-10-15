package installplan

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
)

func adoptionRenderFixture() (*InstallPlan, RenderOptions) {
	const identity = "11111111-1111-1111-1111-111111111111"
	p := &InstallPlan{SchemaVersion: CurrentSchemaVersion, Bridge: BridgeConfig{SSHHost: "192.0.2.1", ReuseSpec: true}, Exits: []ExitNode{{Name: "primary", SSHHost: "192.0.2.2", DialAddr: "exit.example.com", Port: 9443}}}
	completePlanFixture(p)
	bridge := &config.Spec{SchemaVersion: config.CurrentSpecSchemaVersion, Role: config.RoleBridge, MimicPreset: "steamlike", VLESSPort: 7443, PublicHost: "vpn.example.com", GeoAssetsDir: "/srv/ultra/geo", Reality: config.RealitySpec{PrivateKey: "fixture-private", PublicKey: "fixture-public", Dest: "example.com:443", ServerNames: []string{"example.com"}}, Exit: config.ExitTunnelSpec{Address: "exit.example.com", Port: 9443, TunnelUUID: identity, PinnedPeerCertSHA256: "fixture-pin"}, SplithttpPath: "/installed", SplithttpHost: "example.com", TunnelTransport: config.TunnelTransportGRPC, AntiCensor: &config.AntiCensorSpec{Profile: "stealth", SplitHTTPPadding: "100-1000", SplitHTTPMaxChunkKB: 64, DisableDOH: true}, BotTelegramProxy: &config.BotTelegramProxySpec{Enabled: true, Port: 10819}, ExitCertPaths: config.CertPaths{CertFile: "/srv/ultra/bridge.pem", KeyFile: "/srv/ultra/bridge.key"}, Database: &config.DatabaseSpec{DSN: "postgres://fixture:fixture@127.0.0.1:5432/fixture?sslmode=disable"}}
	exit := &config.Spec{SchemaVersion: config.CurrentSpecSchemaVersion, Role: config.RoleExit, MimicPreset: "steamlike", VLESSPort: 9443, Exit: config.ExitTunnelSpec{TunnelUUID: identity}, SplithttpPath: "/installed", SplithttpHost: "example.com", TunnelTransport: config.TunnelTransportGRPC, ExitCertPaths: config.CertPaths{CertFile: "/etc/ultra-relay/fullchain.pem", KeyFile: "/etc/ultra-relay/privkey.pem"}, AntiCensor: &config.AntiCensorSpec{Profile: "stealth", WARPProxy: true, WARPProxyPort: 40123}}
	bridgeJSON, _ := json.Marshal(bridge)
	exitJSON, _ := json.Marshal(exit)
	return p, RenderOptions{ExistingBridgeJSON: bridgeJSON, ExistingExitJSON: map[string][]byte{"primary": exitJSON}, PreserveRuntime: true, ExistingBridge: bridge, ExistingExits: map[string]*config.Spec{"primary": exit}, ExistingAdminToken: "fixture-admin", PriorBootstrap: []exits.BootstrapEntry{{Name: "primary", Address: "exit.example.com", Port: 9443, TunnelUUID: identity, Priority: 250, Enabled: exits.BootstrapEnabledPtr(false), PinnedPeerCertSHA256: "fixture-pin"}}}
}

func TestRenderAdoptionPreservesReviewedRuntime(t *testing.T) {
	p, opts := adoptionRenderFixture()
	bridgeBefore, _ := json.Marshal(opts.ExistingBridge)
	exitBefore, _ := json.Marshal(opts.ExistingExits["primary"])
	ds, err := RenderDesiredStateWithOptions(p, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ds.BridgeSpecObject, opts.ExistingBridge) {
		t.Fatal("adoption changed installed bridge runtime")
	}
	if !reflect.DeepEqual(ds.ExitSpecObjects["primary"], opts.ExistingExits["primary"]) {
		t.Fatal("adoption changed installed exit runtime")
	}
	if !reflect.DeepEqual(ds.Bootstrap, opts.PriorBootstrap) {
		t.Fatal("adoption changed exit topology, priority, enabled state or certificate pin")
	}
	if ds.AdminToken != opts.ExistingAdminToken || ds.TunnelUUIDs["primary"] != opts.PriorBootstrap[0].TunnelUUID || ds.PostgresConfig != nil {
		t.Fatal("adoption generated or reprovisioned identity")
	}
	if ds.DBDSN != opts.ExistingBridge.Database.DSN {
		t.Fatal("adoption lost installed database identity")
	}
	var decoded config.Spec
	if err = json.Unmarshal(ds.BridgeSpec, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(&decoded, opts.ExistingBridge) {
		t.Fatal("serialized bridge differs from reviewed runtime")
	}
	ds.BridgeSpecObject.Reality.ServerNames[0] = "changed.example.net"
	ds.ExitSpecObjects["primary"].AntiCensor.WARPProxyPort = 49999
	*ds.Bootstrap[0].Enabled = true
	bridgeAfter, _ := json.Marshal(opts.ExistingBridge)
	exitAfter, _ := json.Marshal(opts.ExistingExits["primary"])
	if string(bridgeBefore) != string(bridgeAfter) || string(exitBefore) != string(exitAfter) || opts.PriorBootstrap[0].EnabledOrDefault() {
		t.Fatal("adoption mutated source snapshot")
	}
}

func TestRenderAdoptionRejectsUnprovedTopology(t *testing.T) {
	tests := []struct {
		name   string
		change func(*InstallPlan, *RenderOptions)
	}{
		{"not reuse", func(p *InstallPlan, _ *RenderOptions) {
			p.Bridge.ReuseSpec = false
			p.Bridge.RealityDest = "example.com:443"
		}},
		{"missing bridge", func(_ *InstallPlan, o *RenderOptions) { o.ExistingBridge = nil }},
		{"wrong bridge role", func(_ *InstallPlan, o *RenderOptions) { o.ExistingBridge.Role = config.RoleExit }},
		{"missing admin identity", func(_ *InstallPlan, o *RenderOptions) { o.ExistingAdminToken = "" }},
		{"missing static exit", func(_ *InstallPlan, o *RenderOptions) { delete(o.ExistingExits, "primary") }},
		{"wrong exit role", func(_ *InstallPlan, o *RenderOptions) { o.ExistingExits["primary"].Role = config.RoleBridge }},
		{"invalid installed spec", func(_ *InstallPlan, o *RenderOptions) { o.ExistingExits["primary"].ExitCertPaths.KeyFile = "" }},
		{"noncanonical exit certificate", func(_ *InstallPlan, o *RenderOptions) {
			o.ExistingExits["primary"].ExitCertPaths.CertFile = "/srv/ultra/exit.pem"
		}},
		{"noncanonical exit key", func(_ *InstallPlan, o *RenderOptions) {
			o.ExistingExits["primary"].ExitCertPaths.KeyFile = "/srv/ultra/exit.key"
		}},
		{"missing bootstrap", func(_ *InstallPlan, o *RenderOptions) { o.PriorBootstrap = nil }},
		{"duplicate route", func(_ *InstallPlan, o *RenderOptions) {
			entry := o.PriorBootstrap[0]
			entry.Name = "duplicate"
			o.PriorBootstrap = append(o.PriorBootstrap, entry)
		}},
		{"duplicate name", func(_ *InstallPlan, o *RenderOptions) {
			entry := o.PriorBootstrap[0]
			entry.Address = "other.example.com"
			o.PriorBootstrap = append(o.PriorBootstrap, entry)
		}},
		{"empty route identity", func(_ *InstallPlan, o *RenderOptions) { o.PriorBootstrap[0].TunnelUUID = "" }},
		{"active bridge identity mismatch", func(_ *InstallPlan, o *RenderOptions) {
			o.ExistingBridge.Exit.TunnelUUID = "22222222-2222-2222-2222-222222222222"
		}},
		{"static identity mismatch", func(_ *InstallPlan, o *RenderOptions) {
			o.ExistingExits["primary"].Exit.TunnelUUID = "22222222-2222-2222-2222-222222222222"
		}},
		{"requested identity mismatch", func(p *InstallPlan, _ *RenderOptions) { p.Exits[0].TunnelUUID = "22222222-2222-2222-2222-222222222222" }},
		{"static address mismatch", func(p *InstallPlan, _ *RenderOptions) { p.Exits[0].DialAddr = "other.example.com" }},
		{"static port mismatch", func(_ *InstallPlan, o *RenderOptions) { o.ExistingExits["primary"].VLESSPort = 9444 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, opts := adoptionRenderFixture()
			tt.change(p, &opts)
			opts.ExistingBridgeJSON, _ = json.Marshal(opts.ExistingBridge)
			opts.ExistingExitJSON["primary"], _ = json.Marshal(opts.ExistingExits["primary"])
			if _, err := RenderDesiredStateWithOptions(p, opts); err == nil {
				t.Fatal("adoption accepted unproved runtime identity or topology")
			}
		})
	}
}

func TestRenderAdoptionPreservesActiveDynamicExit(t *testing.T) {
	p, opts := adoptionRenderFixture()
	dynamic := exits.BootstrapEntry{Name: "dynamic", Address: "dynamic.example.com", Port: 8443, TunnelUUID: "22222222-2222-2222-2222-222222222222", Priority: 75}
	opts.PriorBootstrap = append(opts.PriorBootstrap, dynamic)
	opts.ExistingBridge.Exit = config.ExitTunnelSpec{Address: dynamic.Address, Port: dynamic.Port, TunnelUUID: dynamic.TunnelUUID}
	opts.ExistingBridgeJSON, _ = json.Marshal(opts.ExistingBridge)
	ds, err := RenderDesiredStateWithOptions(p, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ds.Bootstrap, opts.PriorBootstrap) || ds.BridgeSpecObject.Exit != opts.ExistingBridge.Exit {
		t.Fatal("adoption removed dynamic route or reset active exit to first static node")
	}
}

func TestRenderAdoptionOptInRetainsNormalRenderSemantics(t *testing.T) {
	p, opts := adoptionRenderFixture()
	opts.PreserveRuntime = false
	ds, err := RenderDesiredStateWithOptions(p, opts)
	if err != nil {
		t.Fatal(err)
	}
	if ds.BridgeSpecObject.VLESSPort != 443 || ds.ExitSpecObjects["primary"].TunnelTransport != config.TunnelTransportSplitHTTP || ds.BridgeEnv == "" {
		t.Fatal("ordinary reuse no longer renders plan defaults")
	}
	p.Bridge.ReuseSpec = false
	p.Bridge.RealityDest = "example.com:443"
	ds, err = RenderDesiredStateWithOptions(p, RenderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if ds.AdminToken == "" || ds.TunnelUUIDs["primary"] == "" || ds.BridgeSpecObject.Reality.PrivateKey == "fixture-private" {
		t.Fatal("new installation no longer generates fresh identities")
	}
}

func TestRenderAdoptionPreservesOriginalJSONRouting(t *testing.T) {
	p, opts := adoptionRenderFixture()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(opts.ExistingBridgeJSON, &raw); err != nil {
		t.Fatal(err)
	}
	// The accepted source distinguishes [] from omitted/null, and may carry
	// fields which this installer version does not know how to serialize.
	raw["routing_mode"] = json.RawMessage(`"ru_direct"`)
	raw["ru_direct_tld_regex"] = json.RawMessage(`false`)
	raw["geoip_direct_tags"] = json.RawMessage(`[]`)
	raw["geosite_direct_tags"] = json.RawMessage(`[]`)
	raw["domain_direct"] = json.RawMessage(`[]`)
	raw["probe_urls"] = json.RawMessage(`[]`)
	raw["future_setting"] = json.RawMessage(`{"enabled":false,"values":[]}`)
	var err error
	opts.ExistingBridgeJSON, err = json.MarshalIndent(raw, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(opts.ExistingBridgeJSON, &opts.ExistingBridge); err != nil {
		t.Fatal(err)
	}
	strat, err := mimic.New(opts.ExistingBridge.MimicPreset)
	if err != nil {
		t.Fatal(err)
	}
	before, err := config.BuildBridgeXRayJSON(opts.ExistingBridge, nil, nil, "", strat, "warning")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(before, []byte("geoip:ru")) || bytes.Contains(before, []byte("geoip:private")) {
		t.Fatal("fixture did not disable geoip direct routing")
	}
	ds, err := RenderDesiredStateWithOptions(p, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ds.BridgeSpec, opts.ExistingBridgeJSON) || !bytes.Equal(ds.ExitSpecs["primary"], opts.ExistingExitJSON["primary"]) {
		t.Fatal("adoption changed the accepted source JSON")
	}
	var afterSpec config.Spec
	if err = json.Unmarshal(ds.BridgeSpec, &afterSpec); err != nil {
		t.Fatal(err)
	}
	if afterSpec.GeoipDirectTags == nil || afterSpec.GeositeDirectTags == nil || afterSpec.DomainDirect == nil || afterSpec.ProbeURLs == nil {
		t.Fatal("adoption lost explicit empty arrays")
	}
	if afterSpec.RuDirectTLDRegex == nil || *afterSpec.RuDirectTLDRegex {
		t.Fatal("adoption lost explicit false options")
	}
	after, err := config.BuildBridgeXRayJSON(&afterSpec, nil, nil, "", strat, "warning")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("adoption changed generated routing configuration")
	}
	// Returned bytes, like objects, must not alias the inspected snapshot.
	ds.BridgeSpec[0] = ' '
	ds.ExitSpecs["primary"][0] = ' '
	if opts.ExistingBridgeJSON[0] != '{' || opts.ExistingExitJSON["primary"][0] != '{' {
		t.Fatal("adoption mutated source JSON")
	}
}

func TestRenderAdoptionRequiresMatchingSupportedRawJSON(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*RenderOptions)
	}{
		{"missing bridge raw", func(o *RenderOptions) { o.ExistingBridgeJSON = nil }},
		{"missing exit raw", func(o *RenderOptions) { delete(o.ExistingExitJSON, "primary") }},
		{"malformed bridge raw", func(o *RenderOptions) { o.ExistingBridgeJSON = []byte("{") }},
		{"malformed exit raw", func(o *RenderOptions) { o.ExistingExitJSON["primary"] = []byte("{") }},
		{"mismatched bridge raw", func(o *RenderOptions) { o.ExistingBridge.VLESSPort++ }},
		{"mismatched exit raw", func(o *RenderOptions) { o.ExistingExits["primary"].VLESSPort++ }},
		{"nil versus empty mismatch", func(o *RenderOptions) { o.ExistingBridge.GeoipDirectTags = []string{} }},
		{"unsupported schema", func(o *RenderOptions) {
			o.ExistingBridge.SchemaVersion = config.CurrentSpecSchemaVersion + 1
			o.ExistingBridgeJSON, _ = json.Marshal(o.ExistingBridge)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, opts := adoptionRenderFixture()
			tc.change(&opts)
			if _, err := RenderDesiredStateWithOptions(p, opts); err == nil {
				t.Fatal("adoption accepted missing, mismatched or unsupported original JSON")
			}
		})
	}
}
