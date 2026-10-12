package config

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/NikitaDmitryuk/ultra/internal/proxy"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

func TestExperimentalGatewayTLSAuthAccountingAndRestart(t *testing.T) {
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, strings.Repeat("x", 65536)) }))
	defer destination.Close()
	cert, key := testCertificate(t)
	user := auth.User{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee", Name: "test", IsActive: true, Kind: "vless"}
	spec := bridgeSpecForAntiCensorTest()
	spec.SplitRouting = BoolPtr(false)
	spec.LegacyPublicEnabled = BoolPtr(false)
	spec.PrimaryXHTTP = &PrimaryXHTTPIngress{Host: "127.0.0.1", BackendPort: freePort(t), PublicXHTTPTLSSpec: PublicXHTTPTLSSpec{Port: 443, ServerName: "example.com", Path: "/primary"}}
	spec.GatewayVLESSPort = freePort(t)
	spec.Stats = &StatsSpec{APIListen: net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t)))}
	spec.Database = &DatabaseSpec{}
	strat, _ := mimic.New("steamlike")
	render := func(users []auth.User) []byte {
		raw, err := BuildBridgeXRayJSON(spec, users, nil, "", strat, "error")
		if err != nil {
			t.Fatal(err)
		}
		var cfg map[string]any
		_ = json.Unmarshal(raw, &cfg)
		cfg["outbounds"] = []any{map[string]any{"tag": "direct", "protocol": "freedom", "settings": localFreedomSettings("")}}
		delete(cfg, "routing")
		delete(cfg, "dns")
		raw, _ = json.Marshal(cfg)
		return raw
	}
	var main proxy.Runner
	if err := main.StartJSON(render([]auth.User{user})); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = main.Close() }()
	gatewaySpec := &ExperimentalTransportSpec{BackendPort: spec.GatewayVLESSPort, Profile: ExperimentalProfile{Host: "127.0.0.1", StatusPort: freePort(t), Endpoint: PublicXHTTPTLSSpec{Port: freePort(t), ServerName: "example.com", CertificateFile: cert, KeyFile: key, Path: "/experiment", Mode: "stream-up"}}}
	raw, err := BuildExperimentalGateway(gatewaySpec)
	if err != nil {
		t.Fatal(err)
	}
	var gateway proxy.Runner
	if err = gateway.StartJSON(raw); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gateway.Close() }()
	client := func(experimental bool) *proxy.Runner {
		var outbound map[string]any
		if experimental {
			export := BuildExperimentalExport(spec, user, &gatewaySpec.Profile)
			outbound = export.XRayOutboundJSON
			tls := outbound["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)
			tls["certificates"] = []any{map[string]any{"certificateFile": cert, "usage": "verify"}}
		} else {
			export, _ := BuildClientExport(spec, user)
			outbound = export.XRayOutboundJSON
			next := outbound["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
			next["port"] = spec.PrimaryXHTTP.BackendPort
			stream := outbound["streamSettings"].(map[string]any)
			stream["security"] = "none"
			delete(stream, "tlsSettings")
		}
		data, _ := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "error"}, "outbounds": []any{outbound}})
		runner := new(proxy.Runner)
		if err := runner.StartJSON(data); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = runner.Close() })
		return runner
	}
	primary := client(false)
	experimental := client(true)
	get := func(runner *proxy.Runner) error {
		tr := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d, e := xnet.ParseDestination(network + ":" + addr)
			if e != nil {
				return nil, e
			}
			return core.Dial(ctx, runner.Instance(), d)
		}}
		defer tr.CloseIdleConnections()
		resp, e := (&http.Client{Transport: tr, Timeout: 3 * time.Second}).Get(destination.URL)
		if e != nil {
			return e
		}
		defer func() { _ = resp.Body.Close() }()
		body, e := io.ReadAll(resp.Body)
		if e == nil && len(body) != 65536 {
			t.Fatalf("short body %d", len(body))
		}
		return e
	}
	if err = get(primary); err != nil {
		t.Fatal(err)
	}
	before := main.PeekCounter("user>>>" + user.UUID + ">>>traffic>>>downlink")
	if err = get(experimental); err != nil {
		t.Fatal(err)
	}
	after := main.PeekCounter("user>>>" + user.UUID + ">>>traffic>>>downlink")
	if after-before < 65536 || after-before > 70000 {
		t.Fatalf("traffic not accounted once: %d", after-before)
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, e := udp.ReadFrom(buf)
			if e != nil {
				return
			}
			_, _ = udp.WriteTo(buf[:n], addr)
		}
	}()
	for _, runner := range []*proxy.Runner{primary, experimental} {
		packet, e := core.DialUDP(context.Background(), runner.Instance())
		if e != nil {
			t.Fatal(e)
		}
		_, e = packet.WriteTo([]byte("udp-test"), udp.LocalAddr())
		if e != nil {
			t.Fatal(e)
		}
		_ = packet.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 64)
		n, _, e := packet.ReadFrom(buf)
		_ = packet.Close()
		if e != nil || string(buf[:n]) != "udp-test" {
			t.Fatal("UDP gateway transfer", e)
		}
	}
	count := main.Status().Count
	if err = gateway.Close(); err != nil {
		t.Fatal(err)
	}
	if err = get(primary); err != nil {
		t.Fatal("experiment shutdown affected primary", err)
	}
	if err = gateway.StartJSON(raw); err != nil {
		t.Fatal(err)
	}
	if err = get(experimental); err != nil {
		t.Fatal("experiment restart", err)
	}
	if main.Status().Count != count {
		t.Fatal("main reloaded")
	}
	if err = main.ReloadReason(render(nil), "disable user"); err != nil {
		t.Fatal(err)
	}
	if get(primary) == nil || get(experimental) == nil {
		t.Fatal("disabled UUID still works")
	}
}
