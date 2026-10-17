package config

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/NikitaDmitryuk/ultra/internal/proxy"
	"github.com/NikitaDmitryuk/ultra/internal/realitykey"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

func TestHappBridgeFailoverLocalTransfer(t *testing.T) {
	for _, transport := range []string{"tcp", "xhttp", "mixed"} {
		t.Run(transport, func(t *testing.T) { testHappBridgeFailover(t, transport, "chrome") })
	}
}

func TestHappLegacyClientHelloLocalTransfer(t *testing.T) {
	testHappBridgeFailover(t, "tcp", "hellochrome_120")
}

func testHappBridgeFailover(t *testing.T, transport, fingerprint string) {
	var directRequests atomic.Int64
	directTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		directRequests.Add(1)
		_, _ = io.WriteString(w, "direct")
	}))
	defer directTarget.Close()
	resp, err := http.Get(directTarget.URL + "/data")
	if err != nil {
		t.Fatal("fail-closed target is not independently reachable", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || directRequests.Load() != 1 {
		t.Fatal("fail-closed target did not record the direct control request")
	}
	directRequests.Store(0)
	camouflage := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	camouflage.EnableHTTP2 = true
	camouflage.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	camouflage.StartTLS()
	defer camouflage.Close()
	user := auth.User{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee", Kind: "vless", IsActive: true}
	spec := &Spec{}
	tlsCertificate := ""
	var servers [2]proxy.Runner
	var configs [2][]byte
	strategy, err := mimic.New("apijson")
	if err != nil {
		t.Fatal(err)
	}
	for i := range servers {
		label := fmt.Sprintf("bridge-%d", i)
		destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/generate_204" {
				w.WriteHeader(204)
				return
			}
			_, _ = io.WriteString(w, label)
		}))
		defer destination.Close()
		keys, err := realitykey.Generate()
		if err != nil {
			t.Fatal(err)
		}
		bridge := bridgeSpecForAntiCensorTest()
		bridge.DevMode = false
		bridge.PublicHost, bridge.ListenAddress = "127.0.0.1", "127.0.0.1"
		bridge.VLESSPort = freePort(t)
		bridge.Reality = RealitySpec{
			PrivateKey:  keys.PrivateKey,
			PublicKey:   keys.PublicKey,
			Dest:        camouflage.Listener.Addr().String(),
			ServerNames: []string{"example.com"},
		}
		bridge.AntiCensor = nil
		port := bridge.VLESSPort
		count := 1
		if transport == "xhttp" {
			port = freePort(t)
			bridge.AntiCensor = &AntiCensorSpec{PublicXHTTPPort: port}
			count = 2
		}
		endpoint := SubscriptionBridge{
			ID:          fmt.Sprint(i),
			Host:        "127.0.0.1",
			Port:        port,
			PublicKey:   keys.PublicKey,
			ServerName:  "example.com",
			Transport:   transport,
			Path:        bridge.SplithttpPath,
			Fingerprint: fingerprint,
		}
		if transport == "mixed" {
			endpoint.Transport = "tcp"
			if i == 0 {
				cert, key := testCertificate(t)
				tlsCertificate = cert
				port = freePort(t)
				bridge.LegacyPublicEnabled = BoolPtr(false)
				bridge.PublicXHTTPTLS = &PublicXHTTPTLSSpec{
					Port:            port,
					ServerName:      "example.com",
					Path:            "/mixed",
					Mode:            "stream-up",
					CertificateFile: cert,
					KeyFile:         key,
				}
				endpoint = SubscriptionBridge{
					ID:         fmt.Sprint(i),
					Host:       "127.0.0.1",
					Port:       port,
					Security:   "tls",
					Transport:  "xhttp",
					ServerName: "example.com",
					Path:       "/mixed",
				}
			}
		}
		data, err := BuildBridgeXRayJSON(bridge, []auth.User{user}, nil, "", strategy, "error")
		if err != nil {
			t.Fatal(err)
		}
		var cfg map[string]any
		if err = json.Unmarshal(data, &cfg); err != nil {
			t.Fatal(err)
		}
		// Only the fixture's server egress redirects to a local destination.
		cfg["inbounds"] = cfg["inbounds"].([]any)[:count]
		cfg["outbounds"] = []any{
			map[string]any{"protocol": "freedom", "settings": localFreedomSettings(destination.Listener.Addr().String())},
		}
		delete(cfg, "routing")
		delete(cfg, "dns")
		configs[i], err = json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err = servers[i].StartJSON(configs[i]); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = servers[i].Close() }()
		spec.SubscriptionBridges = append(spec.SubscriptionBridges, endpoint)
	}
	profile, err := BuildHappProfile(spec, user, "Автоматически")
	if err != nil {
		t.Fatal(err)
	}
	if tlsCertificate != "" {
		out := profile["outbounds"].([]any)[1].(map[string]any)
		out["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)["certificates"] = []any{
			map[string]any{"certificateFile": tlsCertificate, "usage": "verify"},
		}
	}
	profile["inbounds"].([]any)[0].(map[string]any)["port"] = freePort(t)
	// A local HTTP probe avoids an external dependency; cadence and strategy stay unchanged.
	profile["burstObservatory"].(map[string]any)["pingConfig"].(map[string]any)["destination"] = directTarget.URL + "/generate_204"
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	var client proxy.Runner
	if err = client.StartJSON(data); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	tr := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		d, err := xnet.ParseDestination(network + ":" + addr)
		if err != nil {
			return nil, err
		}
		return core.Dial(ctx, client.Instance(), d)
	}}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: time.Second}
	request := func() string {
		resp, err := hc.Get(directTarget.URL + "/data")
		if err != nil {
			return ""
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != 200 {
			return ""
		}
		return string(body)
	}
	wait := func(want string) string {
		t.Helper()
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			got := request()
			if got != "" && (want == "" || got == want) {
				return got
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("no working route to %q within 60 seconds", want)
		return ""
	}
	first := wait("")
	failed := 0
	if first == "bridge-1" {
		failed = 1
	}
	if err = servers[failed].Close(); err != nil {
		t.Fatal(err)
	}
	wait(fmt.Sprintf("bridge-%d", 1-failed))
	if err = servers[failed].StartJSON(configs[failed]); err != nil {
		t.Fatal(err)
	}
	if err = servers[1-failed].Close(); err != nil {
		t.Fatal(err)
	}
	wait(fmt.Sprintf("bridge-%d", failed))
	if err = servers[failed].Close(); err != nil {
		t.Fatal(err)
	}
	if got := request(); got != "" {
		t.Fatal("traffic escaped after both bridges stopped", got)
	}
	if directRequests.Load() != 0 {
		t.Fatal("client bypassed bridges to reach the available target directly")
	}
	if client.Status().Count != 1 {
		t.Fatal("client was reloaded during failover")
	}
}
