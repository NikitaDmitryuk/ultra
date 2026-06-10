package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
)

func TestBuildBridgeDevJSON(t *testing.T) {
	spec := &Spec{
		Role:          RoleBridge,
		ListenAddress: "127.0.0.1",
		VLESSPort:     10443,
		PublicHost:    "example.com",
		DevMode:       true,
		SplitRouting:  BoolPtr(false),
		Exit: ExitTunnelSpec{
			Address:    "10.0.0.2",
			Port:       443,
			TunnelUUID: "11111111-2222-3333-4444-555555555555",
		},
	}
	s, err := mimic.New("apijson")
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildBridgeXRayJSON(spec, []auth.User{{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee", Name: "u"}}, nil, "", s, "warning")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	if root["inbounds"] == nil || root["outbounds"] == nil {
		t.Fatal(root)
	}
}

func TestBuildBridgeEmptyClients(t *testing.T) {
	spec := &Spec{
		Role:          RoleBridge,
		ListenAddress: "127.0.0.1",
		VLESSPort:     10444,
		PublicHost:    "example.com",
		DevMode:       true,
		SplitRouting:  BoolPtr(false),
		Exit: ExitTunnelSpec{
			Address:    "10.0.0.2",
			Port:       443,
			TunnelUUID: "11111111-2222-3333-4444-555555555555",
		},
	}
	s, err := mimic.New("apijson")
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildBridgeXRayJSON(spec, nil, nil, "", s, "")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	inbounds, _ := root["inbounds"].([]any)
	if len(inbounds) < 1 {
		t.Fatal("expected inbounds")
	}
	first, _ := inbounds[0].(map[string]any)
	settings, _ := first["settings"].(map[string]any)
	clients, _ := settings["clients"].([]any)
	if clients == nil || len(clients) != 0 {
		t.Fatalf("expected empty clients, got %v", clients)
	}
}

func TestSocks5ClientURI(t *testing.T) {
	u := Socks5ClientURI("vpn.example.com", 1080, "user1", "p@ss/word")
	if u == "" {
		t.Fatal("empty uri")
	}
	if !strings.HasPrefix(u, "socks5://") {
		t.Fatalf("want socks5 scheme: %s", u)
	}
}

func TestBuildClientExportDev(t *testing.T) {
	spec := &Spec{
		Role:       RoleBridge,
		VLESSPort:  443,
		PublicHost: "edge.example.com",
		DevMode:    true,
	}
	exp, err := BuildClientExport(spec, auth.User{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee", Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if exp.VLESSURI == "" || exp.XRayOutboundJSON == nil {
		t.Fatal(exp)
	}
}

func TestBuildBridgeXRayJSONAddsBlackholeWhenBlockTags(t *testing.T) {
	spec := &Spec{
		Role:             RoleBridge,
		ListenAddress:    "127.0.0.1",
		VLESSPort:        10446,
		PublicHost:       "example.com",
		DevMode:          true,
		SplitRouting:     BoolPtr(true),
		GeoAssetsDir:     "/tmp/geo",
		GeositeBlockTags: []string{"category-ads-all"},
		Exit: ExitTunnelSpec{
			Address:    "10.0.0.2",
			Port:       443,
			TunnelUUID: "11111111-2222-3333-4444-555555555555",
		},
	}
	s, err := mimic.New("apijson")
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildBridgeXRayJSON(spec, nil, nil, "", s, "warning")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	out, _ := root["outbounds"].([]any)
	if len(out) != 3 {
		t.Fatalf("expected 3 outbounds (exit, direct, blackhole), got %d", len(out))
	}
	blk, _ := out[2].(map[string]any)
	if blk["protocol"] != "blackhole" {
		t.Fatalf("third outbound: %#v", blk)
	}
}

func TestBuildBridgeXRayJSONSplitUsesMphMatcher(t *testing.T) {
	spec := &Spec{
		Role:          RoleBridge,
		ListenAddress: "127.0.0.1",
		VLESSPort:     10445,
		PublicHost:    "example.com",
		DevMode:       true,
		SplitRouting:  BoolPtr(true),
		GeoAssetsDir:  "/nonexistent-but-unused-for-json",
		Exit: ExitTunnelSpec{
			Address:    "10.0.0.2",
			Port:       443,
			TunnelUUID: "11111111-2222-3333-4444-555555555555",
		},
	}
	s, err := mimic.New("apijson")
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildBridgeXRayJSON(spec, nil, nil, "", s, "warning")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	rt, _ := root["routing"].(map[string]any)
	if rt == nil {
		t.Fatal("missing routing")
	}
	if rt["domainMatcher"] != "mph" {
		t.Fatalf("domainMatcher: got %#v", rt["domainMatcher"])
	}
}

func TestBuildBridgeSOCKS5SecondInbound(t *testing.T) {
	spec := &Spec{
		Role:          RoleBridge,
		ListenAddress: "127.0.0.1",
		VLESSPort:     10443,
		PublicHost:    "example.com",
		DevMode:       true,
		SplitRouting:  BoolPtr(false),
		SOCKS5: &BridgeSOCKS5Spec{
			Enabled:  true,
			Port:     1080,
			Username: "dev",
			Password: "secret",
		},
		Exit: ExitTunnelSpec{
			Address:    "10.0.0.2",
			Port:       443,
			TunnelUUID: "11111111-2222-3333-4444-555555555555",
		},
	}
	s, err := mimic.New("apijson")
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildBridgeXRayJSON(spec, nil, nil, "", s, "warning")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	inbounds, _ := root["inbounds"].([]any)
	if len(inbounds) < 2 {
		t.Fatalf("expected at least 2 inbounds, got %d", len(inbounds))
	}
	var socks map[string]any
	for _, ib := range inbounds {
		m, _ := ib.(map[string]any)
		if m != nil && m["protocol"] == "socks" {
			socks = m
			break
		}
	}
	if socks == nil {
		t.Fatalf("socks inbound not found among %d inbounds", len(inbounds))
	}
	if socks["listen"] != "127.0.0.1" {
		t.Fatalf("socks listen: got %#v want 127.0.0.1", socks["listen"])
	}
}

func TestBuildBridgeSOCKS5DefaultListenNotPublicVLESSBind(t *testing.T) {
	spec := &Spec{
		Role:          RoleBridge,
		ListenAddress: "0.0.0.0",
		VLESSPort:     10443,
		PublicHost:    "example.com",
		DevMode:       true,
		SplitRouting:  BoolPtr(false),
		SOCKS5: &BridgeSOCKS5Spec{
			Enabled:  true,
			Port:     1080,
			Username: "dev",
			Password: "secret",
		},
		Exit: ExitTunnelSpec{
			Address:    "10.0.0.2",
			Port:       443,
			TunnelUUID: "11111111-2222-3333-4444-555555555555",
		},
	}
	s, err := mimic.New("apijson")
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildBridgeXRayJSON(spec, nil, nil, "", s, "warning")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	inbounds, _ := root["inbounds"].([]any)
	var socks map[string]any
	for _, ib := range inbounds {
		m, _ := ib.(map[string]any)
		if m != nil && m["protocol"] == "socks" {
			socks = m
			break
		}
	}
	if socks == nil {
		t.Fatalf("socks inbound not found")
	}
	if socks["listen"] != "127.0.0.1" {
		t.Fatalf("socks listen with public vless bind: got %#v want 127.0.0.1", socks["listen"])
	}
	if socks["tag"] != "socks-in" {
		t.Fatalf("legacy socks tag: got %#v", socks["tag"])
	}
	vless, _ := inbounds[0].(map[string]any)
	if vless["listen"] != "0.0.0.0" {
		t.Fatalf("vless listen: got %#v", vless["listen"])
	}
}

func TestBuildBridgeGRPCJSON(t *testing.T) {
	spec := &Spec{
		Role:            RoleBridge,
		ListenAddress:   "127.0.0.1",
		VLESSPort:       10447,
		PublicHost:      "example.com",
		DevMode:         true,
		SplitRouting:    BoolPtr(false),
		TunnelTransport: TunnelTransportGRPC,
		SplithttpPath:   "/relay/v1/tunnel",
		Exit: ExitTunnelSpec{
			Address:    "10.0.0.2",
			Port:       443,
			TunnelUUID: "11111111-2222-3333-4444-555555555555",
		},
	}
	s, err := mimic.New("apijson")
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildBridgeXRayJSON(spec, nil, nil, "", s, "warning")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	outbounds, _ := root["outbounds"].([]any)
	if len(outbounds) < 1 {
		t.Fatal("expected outbounds")
	}
	exitOut, _ := outbounds[0].(map[string]any)
	ss, _ := exitOut["streamSettings"].(map[string]any)
	if ss["network"] != "grpc" {
		t.Fatalf("expected grpc network, got %v", ss["network"])
	}
	grpcCfg, _ := ss["grpcSettings"].(map[string]any)
	if grpcCfg["serviceName"] != "relay/v1/tunnel" {
		t.Fatalf("unexpected serviceName: %v", grpcCfg["serviceName"])
	}
	if grpcCfg["multiMode"] != true {
		t.Fatalf("expected multiMode true, got %v", grpcCfg["multiMode"])
	}
	if got := int(grpcCfg["initialWindowsSize"].(float64)); got != defaultGRPCInitialWindowSize {
		t.Fatalf("initialWindowsSize = %d, want %d", got, defaultGRPCInitialWindowSize)
	}
}

func TestBuildBridgeSplitHTTPJSON(t *testing.T) {
	spec := &Spec{
		Role:            RoleBridge,
		ListenAddress:   "127.0.0.1",
		VLESSPort:       10447,
		PublicHost:      "example.com",
		DevMode:         true,
		SplitRouting:    BoolPtr(false),
		TunnelTransport: TunnelTransportSplitHTTP,
		SplithttpPath:   "/relay/v1/tunnel",
		Exit: ExitTunnelSpec{
			Address:    "10.0.0.2",
			Port:       443,
			TunnelUUID: "11111111-2222-3333-4444-555555555555",
		},
	}
	s, err := mimic.New("apijson")
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildBridgeXRayJSON(spec, nil, nil, "", s, "warning")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	outbounds, _ := root["outbounds"].([]any)
	exitOut, _ := outbounds[0].(map[string]any)
	ss, _ := exitOut["streamSettings"].(map[string]any)
	if ss["network"] != "splithttp" {
		t.Fatalf("expected splithttp network, got %v", ss["network"])
	}
	splitCfg, _ := ss["splithttpSettings"].(map[string]any)
	if splitCfg["mode"] != "stream-up" {
		t.Fatalf("expected stream-up mode, got %v", splitCfg["mode"])
	}
}

func TestBuildBridgeREALITYFlow(t *testing.T) {
	spec := &Spec{
		Role:          RoleBridge,
		ListenAddress: "127.0.0.1",
		VLESSPort:     443,
		PublicHost:    "example.com",
		SplitRouting:  BoolPtr(false),
		Reality: RealitySpec{
			Dest:        "www.example.com:443",
			ServerNames: []string{"www.example.com"},
			PrivateKey:  "priv",
			PublicKey:   "pub",
			ShortIDs:    []string{""},
		},
		Exit: ExitTunnelSpec{
			Address:    "10.0.0.2",
			Port:       51001,
			TunnelUUID: "11111111-2222-3333-4444-555555555555",
		},
	}
	s, err := mimic.New("apijson")
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildBridgeXRayJSON(spec, []auth.User{{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee"}}, nil, "", s, "warning")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	inbounds, _ := root["inbounds"].([]any)
	vlessIn, _ := inbounds[0].(map[string]any)
	settings, _ := vlessIn["settings"].(map[string]any)
	clients, _ := settings["clients"].([]any)
	client, _ := clients[0].(map[string]any)
	if client["flow"] != DefaultVLESSFlow {
		t.Fatalf("client flow = %v, want %q", client["flow"], DefaultVLESSFlow)
	}
}

func TestBuildClientExportREALITYFlow(t *testing.T) {
	spec := &Spec{
		Role:       RoleBridge,
		VLESSPort:  443,
		PublicHost: "edge.example.com",
		Reality: RealitySpec{
			Dest:        "www.example.com:443",
			ServerNames: []string{"www.example.com"},
			PrivateKey:  "priv",
			PublicKey:   "pub",
			ShortIDs:    []string{""},
		},
	}
	exp, err := BuildClientExport(spec, auth.User{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee", Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	settings, _ := exp.XRayOutboundJSON["settings"].(map[string]any)
	vnext, _ := settings["vnext"].([]any)
	node, _ := vnext[0].(map[string]any)
	users, _ := node["users"].([]any)
	user, _ := users[0].(map[string]any)
	if user["flow"] != DefaultVLESSFlow {
		t.Fatalf("user flow = %v", user["flow"])
	}
	if !strings.Contains(exp.VLESSURI, "flow=xtls-rprx-vision") {
		t.Fatalf("uri missing flow: %s", exp.VLESSURI)
	}
}

func TestBuildClientProfilesPreservesLegacyAndAddsXHTTP(t *testing.T) {
	spec := &Spec{
		Role:       RoleBridge,
		VLESSPort:  443,
		PublicHost: "edge.example.com",
		Reality: RealitySpec{
			Dest:        "www.example.com:443",
			ServerNames: []string{"www.example.com"},
			PrivateKey:  "priv",
			PublicKey:   "pub",
			ShortIDs:    []string{"abcd"},
		},
		AntiCensor: &AntiCensorSpec{
			Profile:             AntiCensorProfileBalanced,
			PublicXHTTPPort:     8443,
			RealityFingerprints: []string{"firefox"},
		},
		SplithttpPath: "/api/v1/subscription",
	}
	user := auth.User{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee", Name: "x"}
	legacy, err := BuildClientExport(spec, user)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := BuildClientProfiles(spec, user)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 {
		t.Fatalf("profiles len = %d, want 2", len(profiles))
	}
	if profiles[0].ID != ClientProfileFastTCPReality {
		t.Fatalf("first profile id = %q", profiles[0].ID)
	}
	if profiles[0].VLESSURI != legacy.VLESSURI {
		t.Fatalf("legacy URI changed:\n%s\n%s", profiles[0].VLESSURI, legacy.VLESSURI)
	}
	if profiles[1].ID != ClientProfileFallbackXHTTPReality {
		t.Fatalf("second profile id = %q", profiles[1].ID)
	}
	if !strings.Contains(profiles[1].VLESSURI, "type=xhttp") {
		t.Fatalf("fallback URI missing xhttp: %s", profiles[1].VLESSURI)
	}
	if !strings.Contains(profiles[1].VLESSURI, "8443") {
		t.Fatalf("fallback URI missing public_xhttp_port: %s", profiles[1].VLESSURI)
	}
	stream, _ := profiles[1].XRayOutboundJSON["streamSettings"].(map[string]any)
	if stream["network"] != "xhttp" {
		t.Fatalf("fallback network = %v", stream["network"])
	}
	rs, _ := stream["realitySettings"].(map[string]any)
	if rs["fingerprint"] != "firefox" {
		t.Fatalf("fallback fingerprint = %v", rs["fingerprint"])
	}
	if rs["spiderX"] == "/" || rs["spiderX"] == "" {
		t.Fatalf("fallback spiderX not per-profile: %v", rs["spiderX"])
	}
	if profiles[1].FullConfigBase64 == "" {
		t.Fatal("fallback full config base64 missing")
	}
}

func TestBuildBridgePublicXHTTPInboundWhenEnabled(t *testing.T) {
	spec := bridgeSpecForAntiCensorTest()
	spec.DevMode = false
	spec.GeoAssetsDir = ""
	spec.AntiCensor = &AntiCensorSpec{PublicXHTTPPort: 8443}
	strat, _ := mimic.New("steamlike")
	b, err := BuildBridgeXRayJSON(spec, []auth.User{{UUID: "aaaaaaaa-0000-0000-0000-000000000001"}}, nil, "", strat, "warning")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	inbounds, _ := root["inbounds"].([]any)
	found := false
	for _, raw := range inbounds {
		in, _ := raw.(map[string]any)
		if in["port"].(float64) != 8443 {
			continue
		}
		stream, _ := in["streamSettings"].(map[string]any)
		if stream["network"] != "xhttp" {
			t.Fatalf("public fallback network = %v", stream["network"])
		}
		found = true
	}
	if !found {
		t.Fatal("public XHTTP inbound not found")
	}
}

func TestBuildBridgePerClientSOCKS5Inbound(t *testing.T) {
	port := 10850
	spec := &Spec{
		Role:          RoleBridge,
		ListenAddress: "127.0.0.1",
		VLESSPort:     10443,
		PublicHost:    "example.com",
		DevMode:       true,
		SplitRouting:  BoolPtr(false),
		SOCKS5: &BridgeSOCKS5Spec{
			Enabled:  true,
			Port:     1080,
			Username: "legacy",
			Password: "legacy-secret",
		},
		Exit: ExitTunnelSpec{
			Address:    "10.0.0.2",
			Port:       443,
			TunnelUUID: "11111111-2222-3333-4444-555555555555",
		},
	}
	s, err := mimic.New("apijson")
	if err != nil {
		t.Fatal(err)
	}
	uid := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	users := []auth.User{
		{UUID: uid, Name: "c1", Kind: "socks5", IsActive: true,
			SocksUsername: uid, SocksPassword: "pw", SocksPort: &port},
	}
	b, err := BuildBridgeXRayJSON(spec, users, nil, "", s, "warning")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	inbounds, _ := root["inbounds"].([]any)
	var legacy, perClient map[string]any
	for _, ib := range inbounds {
		m, _ := ib.(map[string]any)
		if m == nil || m["protocol"] != "socks" {
			continue
		}
		switch m["tag"] {
		case "socks-in":
			legacy = m
		case "socks-" + uid:
			perClient = m
		}
	}
	if legacy == nil {
		t.Fatal("legacy socks-in missing")
	}
	if perClient == nil {
		t.Fatal("per-client socks inbound missing")
	}
	if int(perClient["port"].(float64)) != port {
		t.Fatalf("per-client port: got %v want %d", perClient["port"], port)
	}
	vless, _ := inbounds[0].(map[string]any)
	settings, _ := vless["settings"].(map[string]any)
	clients, _ := settings["clients"].([]any)
	for _, c := range clients {
		cm, _ := c.(map[string]any)
		if cm["id"] == uid {
			t.Fatalf("socks5 user must not appear in VLESS clients: %#v", clients)
		}
	}
}

func TestBuildBridgeMultiExitOutbounds(t *testing.T) {
	spec := &Spec{
		Role:          RoleBridge,
		ListenAddress: "127.0.0.1",
		VLESSPort:     10443,
		PublicHost:    "example.com",
		DevMode:       true,
		SplitRouting:  BoolPtr(false),
		Exit: ExitTunnelSpec{
			Address:    "10.0.0.2",
			Port:       443,
			TunnelUUID: "11111111-2222-3333-4444-555555555555",
		},
	}
	s, err := mimic.New("apijson")
	if err != nil {
		t.Fatal(err)
	}
	exitNodes := []exits.Node{
		{ID: "primary-id", Name: "p", Address: "10.0.0.2", Port: 443, TunnelUUID: "uuid-primary", Priority: 100, Enabled: true},
		{ID: "backup-id", Name: "b", Address: "10.0.0.3", Port: 443, TunnelUUID: "uuid-backup", Priority: 200, Enabled: true},
	}
	b, err := BuildBridgeXRayJSON(spec, nil, exitNodes, "primary-id", s, "warning")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	outbounds, _ := root["outbounds"].([]any)
	tags := map[string]bool{}
	for _, ob := range outbounds {
		m, _ := ob.(map[string]any)
		if m["protocol"] == "vless" {
			tags[m["tag"].(string)] = true
		}
	}
	for _, want := range []string{"to-exit-primary-id", "to-exit-backup-id", "to-exit"} {
		if !tags[want] {
			t.Fatalf("missing outbound %q in %#v", want, tags)
		}
	}
	routing, _ := root["routing"].(map[string]any)
	rules, _ := routing["rules"].([]any)
	var sawActive bool
	for _, r := range rules {
		m, _ := r.(map[string]any)
		if m["outboundTag"] == "to-exit-primary-id" {
			sawActive = true
		}
	}
	if !sawActive {
		t.Fatalf("routing should target active exit outbound: %#v", rules)
	}
}

func TestBuildBridgeExitOutboundsDisabledActive(t *testing.T) {
	spec := &Spec{
		Role:          RoleBridge,
		ListenAddress: "127.0.0.1",
		VLESSPort:     10443,
		PublicHost:    "example.com",
		DevMode:       true,
		SplitRouting:  BoolPtr(false),
		Exit: ExitTunnelSpec{
			Address:    "10.0.0.2",
			Port:       443,
			TunnelUUID: "11111111-2222-3333-4444-555555555555",
		},
	}
	s, err := mimic.New("apijson")
	if err != nil {
		t.Fatal(err)
	}
	exitNodes := []exits.Node{
		{ID: "primary-id", Name: "p", Address: "10.0.0.2", Port: 443, TunnelUUID: "uuid-primary", Priority: 100, Enabled: false},
		{ID: "backup-id", Name: "b", Address: "10.0.0.3", Port: 443, TunnelUUID: "uuid-backup", Priority: 200, Enabled: true},
	}
	b, err := BuildBridgeXRayJSON(spec, nil, exitNodes, "primary-id", s, "warning")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	outbounds, _ := root["outbounds"].([]any)
	tags := map[string]bool{}
	for _, ob := range outbounds {
		m, _ := ob.(map[string]any)
		if m["protocol"] == "vless" {
			tags[m["tag"].(string)] = true
		}
	}
	for _, want := range []string{"to-exit-backup-id", "to-exit"} {
		if !tags[want] {
			t.Fatalf("missing outbound %q in %#v", want, tags)
		}
	}
}

func TestBuildBridgeBotTelegramProxy(t *testing.T) {
	spec := &Spec{
		Role:          RoleBridge,
		ListenAddress: "127.0.0.1",
		VLESSPort:     10443,
		PublicHost:    "example.com",
		DevMode:       true,
		SplitRouting:  BoolPtr(false),
		BotTelegramProxy: &BotTelegramProxySpec{
			Enabled: true,
		},
		Exit: ExitTunnelSpec{
			Address:    "10.0.0.2",
			Port:       443,
			TunnelUUID: "11111111-2222-3333-4444-555555555555",
		},
	}
	s, err := mimic.New("apijson")
	if err != nil {
		t.Fatal(err)
	}
	exitNodes := []exits.Node{
		{ID: "primary-id", Name: "p", Address: "10.0.0.2", Port: 443, TunnelUUID: "uuid-primary", Priority: 100, Enabled: true},
	}
	b, err := BuildBridgeXRayJSON(spec, nil, exitNodes, "primary-id", s, "warning")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	inbounds, _ := root["inbounds"].([]any)
	var botSocks map[string]any
	for _, ib := range inbounds {
		m, _ := ib.(map[string]any)
		if m != nil && m["tag"] == BotTelegramProxyInboundTag {
			botSocks = m
			break
		}
	}
	if botSocks == nil {
		t.Fatal("bot-telegram-socks inbound not found")
	}
	if botSocks["listen"] != "127.0.0.1" || int(botSocks["port"].(float64)) != botTelegramProxyDefaultPort {
		t.Fatalf("bot telegram proxy inbound: got listen=%#v port=%#v", botSocks["listen"], botSocks["port"])
	}
	routing, _ := root["routing"].(map[string]any)
	rules, _ := routing["rules"].([]any)
	var sawBotRule bool
	for _, r := range rules {
		m, _ := r.(map[string]any)
		tags, _ := m["inboundTag"].([]any)
		if len(tags) == 1 && tags[0] == BotTelegramProxyInboundTag && m["outboundTag"] == "to-exit-primary-id" {
			sawBotRule = true
			break
		}
	}
	if !sawBotRule {
		t.Fatalf("missing bot telegram proxy routing rule: %#v", rules)
	}
}
