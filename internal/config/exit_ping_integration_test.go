package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/NikitaDmitryuk/ultra/internal/proxy"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

func TestExitPingActualUserTunnel(t *testing.T) {
	for _, transport := range []TunnelTransport{TunnelTransportSplitHTTP, TunnelTransportGRPC} {
		t.Run(string(transport), func(t *testing.T) { testExitPingActualUserTunnel(t, transport) })
	}
}

func testExitPingActualUserTunnel(t *testing.T, transport TunnelTransport) {
	cert, key := testCertificate(t)
	raw, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	pin := sha256.Sum256(block.Bytes)
	strategy, err := mimic.New("apijson")
	if err != nil {
		t.Fatal(err)
	}
	s := &Spec{
		Role: RoleBridge, ListenAddress: "127.0.0.1", PublicHost: "127.0.0.1", VLESSPort: freePort(t), DevMode: true,
		ExitPing: true, SplitRouting: BoolPtr(true), RoutingMode: RoutingModeRUDirect,
		GeoipDirectTags: []string{}, RuDirectTLDRegex: BoolPtr(false),
		DomainDirect:    []string{"full:example.net"},
		TunnelTransport: transport, TunnelTLSProvision: TunnelTLSSelfSigned,
		SplithttpPath: "/exit-ping-test", SplithttpHost: "example.com", SplitHTTPTLS: SplitHTTPTLSSpec{ServerName: "example.com"},
	}
	nodes := []exits.Node{
		{
			ID:                   "primary",
			Address:              "127.0.0.1",
			Port:                 freePort(t),
			TunnelUUID:           "2784871e-d8a9-4e1f-b831-3d86aa8653ee",
			PinnedPeerCertSHA256: hex.EncodeToString(pin[:]),
			Enabled:              true,
		},
		{
			ID:                   "reserve",
			Address:              "127.0.0.1",
			Port:                 freePort(t),
			TunnelUUID:           "2784871e-d8a9-4e1f-b831-3d86aa8653ef",
			PinnedPeerCertSHA256: hex.EncodeToString(pin[:]),
			Enabled:              true,
		},
	}
	var counts [2]atomic.Int32
	var targets [2]*httptest.Server
	var servers [2]proxy.Runner
	var exitSpecs [2]Spec
	for i, n := range nodes {
		targets[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			counts[i].Add(1)
			if i == 1 {
				time.Sleep(200 * time.Millisecond)
			}
			if r.URL.Path != ExitPingPath {
				t.Errorf("unexpected responder path: %s", r.URL.Path)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer targets[i].Close()
		exitSpecs[i] = *s
		es := &exitSpecs[i]
		es.Role = RoleExit
		es.VLESSPort = n.Port
		es.Exit = ExitTunnelSpec{TunnelUUID: n.TunnelUUID}
		es.ExitCertPaths = CertPaths{CertFile: cert, KeyFile: key}
		// An unreachable WARP socket proves that the synthetic route bypasses WARP.
		if i == 0 {
			es.AntiCensor = &AntiCensorSpec{WARPProxy: true, WARPProxyPort: freePort(t)}
		}
		data, e := BuildExitXRayJSONWithPingPort(es, strategy, "error", targets[i].Listener.Addr().(*net.TCPAddr).Port)
		if e != nil {
			t.Fatal(e)
		}
		if e = servers[i].StartJSON(data); e != nil {
			t.Fatal(e)
		}
		defer func() { _ = servers[i].Close() }()
	}
	users := []auth.User{
		{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653f0"},
		{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653f1", EffectiveExitID: "reserve"},
		{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653f2", EffectiveExitID: auth.BlockedExit},
		{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653f3", ServiceTargets: []string{"https://example.com/"}},
	}
	var bridge proxy.Runner
	defer func() { _ = bridge.Close() }()
	apply := func() {
		data, e := BuildBridgeXRayJSON(s, users, nodes, "primary", strategy, "error")
		if e != nil {
			t.Fatal(e)
		}
		// The fixed admin health listener is unrelated to this topology and would
		// collide with other integration packages running at the same time.
		var cfg map[string]any
		if e = json.Unmarshal(data, &cfg); e != nil {
			t.Fatal(e)
		}
		cfg["inbounds"] = cfg["inbounds"].([]any)[:1]
		data, e = json.Marshal(cfg)
		if e != nil {
			t.Fatal(e)
		}
		if e = bridge.Reload(data); e != nil {
			t.Fatal(e)
		}
	}
	apply()
	clients := make([]*http.Client, len(users))
	for i, u := range users {
		export, e := BuildClientExport(s, u)
		if e != nil {
			t.Fatal(e)
		}
		data, e := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "none"}, "outbounds": []any{export.XRayOutboundJSON}})
		if e != nil {
			t.Fatal(e)
		}
		c := new(proxy.Runner)
		if e = c.StartJSON(data); e != nil {
			t.Fatal(e)
		}
		defer func() { _ = c.Close() }()
		tr := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d, e := xnet.ParseDestination(network + ":" + addr)
			if e != nil {
				return nil, e
			}
			return core.Dial(ctx, c.Instance(), d)
		}}
		defer tr.CloseIdleConnections()
		clients[i] = &http.Client{Transport: tr, Timeout: 2 * time.Second}
	}
	request := func(i int, method, url string, success bool) time.Duration {
		t.Helper()
		req, e := http.NewRequest(method, url, nil)
		if e != nil {
			t.Fatal(e)
		}
		// A domain that ordinary split routing sends directly must not replace
		// the reserved destination during HTTP sniffing on either relay.
		if req.URL.Hostname() == ExitPingIPv4 {
			req.Host = "example.net"
		}
		start := time.Now()
		resp, e := clients[i].Do(req)
		elapsed := time.Since(start)
		if e != nil {
			if success {
				t.Fatal(e)
			}
			return elapsed
		}
		body, e := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if !success {
			t.Fatalf("restricted request succeeded: client=%d url=%s status=%d", i, url, resp.StatusCode)
		}
		if e != nil || resp.StatusCode != 204 || len(body) != 0 {
			t.Fatalf("probe: status=%d body=%q err=%v", resp.StatusCode, body, e)
		}
		return elapsed
	}
	request(0, "GET", ExitPingURL, true)
	delayed := request(1, "HEAD", ExitPingURL, true)
	if delayed < 200*time.Millisecond {
		t.Fatal("controlled responder delay was bypassed")
	}
	if counts[0].Load() != 1 || counts[1].Load() != 1 {
		t.Fatalf("wrong effective exit: %d/%d", counts[0].Load(), counts[1].Load())
	}
	request(2, "GET", ExitPingURL, false)
	request(3, "HEAD", ExitPingURL, false)
	request(0, "GET", "http://"+ExitPingIPv4+":81"+ExitPingPath, false)
	// The exact loopback exception must not permit direct access to that listener
	// or to any other private address on the normal freedom outbound.
	request(1, "GET", targets[1].URL+ExitPingPath, false)
	if counts[0].Load() != 1 || counts[1].Load() != 1 {
		t.Fatal("restricted credential or destination reached responder")
	}
	// Closing the selected endpoint must not retry against another exit or bridge.
	targets[1].Close()
	request(1, "GET", ExitPingURL, false)
	if counts[0].Load() != 1 {
		t.Fatal("unavailable selected responder fell back to primary")
	}
	// Missing runtime responder and disabled exit both fail closed under WARP.
	data, e := BuildExitXRayJSON(&exitSpecs[0], strategy, "error")
	if e != nil {
		t.Fatal(e)
	}
	if e = servers[0].Reload(data); e != nil {
		t.Fatal(e)
	}
	request(0, "GET", ExitPingURL, false)
	exitSpecs[0].ExitPing = false
	data, e = BuildExitXRayJSONWithPingPort(&exitSpecs[0], strategy, "error", targets[0].Listener.Addr().(*net.TCPAddr).Port)
	if e != nil {
		t.Fatal(e)
	}
	if e = servers[0].Reload(data); e != nil {
		t.Fatal(e)
	}
	request(0, "GET", ExitPingURL, false)
	// Restore an enabled, healthy exit: only the disabled bridge must reject it.
	exitSpecs[0].ExitPing = true
	data, e = BuildExitXRayJSONWithPingPort(&exitSpecs[0], strategy, "error", targets[0].Listener.Addr().(*net.TCPAddr).Port)
	if e != nil {
		t.Fatal(e)
	}
	if e = servers[0].Reload(data); e != nil {
		t.Fatal(e)
	}
	s.ExitPing = false
	apply()
	request(0, "GET", ExitPingURL, false)
	if counts[0].Load() != 1 {
		t.Fatal("disabled route reached responder")
	}
}
