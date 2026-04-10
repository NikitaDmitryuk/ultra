package config

import (
	"encoding/json"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
)

func bridgeSpecForAntiCensorTest() *Spec {
	return &Spec{
		SchemaVersion: 1,
		Role:          RoleBridge,
		ListenAddress: "0.0.0.0",
		VLESSPort:     443,
		PublicHost:    "1.2.3.4",
		Reality: RealitySpec{
			Dest:        "www.yandex.ru:443",
			ServerNames: []string{"www.yandex.ru"},
			PrivateKey:  "fake_priv",
			PublicKey:   "fake_pub",
		},
		Exit: ExitTunnelSpec{
			Address:    "5.6.7.8",
			Port:       51001,
			TunnelUUID: "00000000-0000-0000-0000-000000000001",
		},
		SplithttpPath:      "/api/v1/data",
		TunnelTLSProvision: TunnelTLSSelfSigned,
		SplitHTTPTLS: SplitHTTPTLSSpec{
			ServerName:  "store.steampowered.com",
			Alpn:        []string{"h2"},
			Fingerprint: "chrome",
		},
		GeoAssetsDir: "/tmp/geo",
		DevMode:      true, // skip geo file check
	}
}

func TestAntiCensorDefaults(t *testing.T) {
	spec := bridgeSpecForAntiCensorTest()
	spec.DevMode = true
	strat, _ := mimic.New("steamlike")
	users := []auth.User{{Name: "alice", UUID: "aaaaaaaa-0000-0000-0000-000000000001"}}

	b, err := BuildBridgeXRayJSON(spec, users, strat, "info")
	if err != nil {
		t.Fatal(err)
	}

	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}

	outbounds := cfg["outbounds"].([]any)
	exitOB := outbounds[0].(map[string]any)
	stream := exitOB["streamSettings"].(map[string]any)

	// 1. sockopt.fragment must be present by default
	sockopt, ok := stream["sockopt"].(map[string]any)
	if !ok {
		t.Fatal("expected sockopt in outbound streamSettings")
	}
	frag, ok := sockopt["fragment"].(map[string]any)
	if !ok {
		t.Fatal("expected fragment in sockopt")
	}
	if frag["packets"] != "tlshello" {
		t.Errorf("fragment.packets = %v, want tlshello", frag["packets"])
	}

	// 2. splithttpSettings must have xPaddingSize by default
	sph := stream["splithttpSettings"].(map[string]any)
	if sph["xPaddingSize"] == nil {
		t.Error("expected xPaddingSize in splithttpSettings by default")
	}

	// 3. REALITY fingerprint must be one of the known pool values (rotation)
	// (DevMode skips reality so we check via inbound[0] only in non-DevMode)
	t.Log("sockopt fragment:", frag)
	t.Log("xPaddingSize:", sph["xPaddingSize"])
}

func TestAntiCensorFragmentDisable(t *testing.T) {
	spec := bridgeSpecForAntiCensorTest()
	spec.DevMode = true
	spec.AntiCensor = &AntiCensorSpec{
		Fragment: &FragmentSpec{}, // Packets="" → disabled
	}
	strat, _ := mimic.New("steamlike")

	b, _ := BuildBridgeXRayJSON(spec, nil, strat, "info")
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}

	outbounds := cfg["outbounds"].([]any)
	exitOB := outbounds[0].(map[string]any)
	stream := exitOB["streamSettings"].(map[string]any)
	if _, ok := stream["sockopt"]; ok {
		t.Error("sockopt should be absent when fragment disabled")
	}
}

func TestAntiCensorPaddingDisable(t *testing.T) {
	spec := bridgeSpecForAntiCensorTest()
	spec.DevMode = true
	spec.AntiCensor = &AntiCensorSpec{
		SplitHTTPPadding: "0",
	}
	strat, _ := mimic.New("steamlike")

	b, _ := BuildBridgeXRayJSON(spec, nil, strat, "info")
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}

	outbounds := cfg["outbounds"].([]any)
	exitOB := outbounds[0].(map[string]any)
	stream := exitOB["streamSettings"].(map[string]any)
	sph := stream["splithttpSettings"].(map[string]any)
	if sph["xPaddingSize"] != nil {
		t.Errorf("xPaddingSize should be absent when SplitHTTPPadding=0, got %v", sph["xPaddingSize"])
	}
}

func TestAntiCensorFingerprintPool(t *testing.T) {
	spec := bridgeSpecForAntiCensorTest()
	spec.DevMode = false // use REALITY inbound
	spec.GeoAssetsDir = ""
	// Override pool to a single value to make test deterministic
	spec.AntiCensor = &AntiCensorSpec{
		RealityFingerprints: []string{"firefox"},
	}
	strat, _ := mimic.New("steamlike")

	b, err := BuildBridgeXRayJSON(spec, nil, strat, "info")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}

	inbounds := cfg["inbounds"].([]any)
	inbound := inbounds[0].(map[string]any)
	stream := inbound["streamSettings"].(map[string]any)
	rs := stream["realitySettings"].(map[string]any)
	if rs["fingerprint"] != "firefox" {
		t.Errorf("fingerprint = %v, want firefox", rs["fingerprint"])
	}
}

func TestDoHInBridgeConfig(t *testing.T) {
	spec := bridgeSpecForAntiCensorTest()
	spec.DevMode = false
	strat, _ := mimic.New("steamlike")

	b, err := BuildBridgeXRayJSON(spec, nil, strat, "info")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}

	dns, ok := cfg["dns"].(map[string]any)
	if !ok {
		t.Fatal("dns section missing from bridge config")
	}
	servers := dns["servers"].([]any)
	if len(servers) == 0 {
		t.Fatal("dns.servers is empty")
	}
	// First server should be Yandex DoH for Russian domains
	first := servers[0].(map[string]any)
	if addr, _ := first["address"].(string); addr == "" {
		t.Error("first DNS server has no address")
	} else {
		t.Log("bridge primary DNS server:", addr)
	}
}

func TestWARPExitConfig(t *testing.T) {
	spec := &Spec{
		SchemaVersion: 1,
		Role:          RoleExit,
		VLESSPort:     51001,
		ListenAddress: "0.0.0.0",
		Exit:          ExitTunnelSpec{TunnelUUID: "aaaaaaaa-0000-0000-0000-000000000001"},
		SplithttpPath: "/api/v1",
		SplitHTTPTLS:  SplitHTTPTLSSpec{ServerName: "store.steampowered.com", Alpn: []string{"h2"}, Fingerprint: "chrome"},
		ExitCertPaths: CertPaths{CertFile: "/tmp/cert.pem", KeyFile: "/tmp/key.pem"},
		AntiCensor: &AntiCensorSpec{
			WARPProxy:     true,
			WARPProxyPort: 40000,
		},
	}
	strat, _ := mimic.New("steamlike")
	b, err := BuildExitXRayJSON(spec, strat, "info")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}

	outbounds := cfg["outbounds"].([]any)
	direct := outbounds[0].(map[string]any)
	if direct["protocol"] != "socks" {
		t.Errorf("exit direct outbound protocol = %v, want socks (WARP)", direct["protocol"])
	}
	settings := direct["settings"].(map[string]any)
	servers := settings["servers"].([]any)
	srv := servers[0].(map[string]any)
	if srv["address"] != "127.0.0.1" || srv["port"].(float64) != 40000 {
		t.Errorf("WARP socks server = %v:%v, want 127.0.0.1:40000", srv["address"], srv["port"])
	}
	t.Log("WARP outbound correct:", direct["protocol"], srv["address"], srv["port"])
}
