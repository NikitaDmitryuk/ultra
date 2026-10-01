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
	"strings"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/NikitaDmitryuk/ultra/internal/proxy"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

// Keep client credentials and the client core unchanged across real bridge reloads.
func TestAutoFailoverWithFixedLocationLocalTransfer(t *testing.T) {
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
	spec := &Spec{Role: RoleBridge, ListenAddress: "127.0.0.1", PublicHost: "127.0.0.1", VLESSPort: freePort(t), DevMode: true, SplitRouting: BoolPtr(false), TunnelTLSProvision: TunnelTLSSelfSigned, SplithttpPath: "/failover", SplithttpHost: "example.com", SplitHTTPTLS: SplitHTTPTLSSpec{ServerName: "example.com"}}
	nodes := []exits.Node{
		{ID: "primary", Address: "127.0.0.1", Port: freePort(t), TunnelUUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee", PinnedPeerCertSHA256: hex.EncodeToString(pin[:]), Enabled: true, Priority: 100},
		{ID: "reserve", Address: "127.0.0.1", Port: freePort(t), TunnelUUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ef", PinnedPeerCertSHA256: hex.EncodeToString(pin[:]), Enabled: true, Priority: 200},
	}
	var exitRunners [2]proxy.Runner
	var exitConfigs [2][]byte
	for i, n := range nodes {
		payload := strings.Repeat(string(rune('a'+i)), 65536)
		destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, payload) }))
		defer destination.Close()
		exitSpec := *spec
		exitSpec.Role = RoleExit
		exitSpec.VLESSPort = n.Port
		exitSpec.Exit = ExitTunnelSpec{TunnelUUID: n.TunnelUUID}
		exitSpec.ExitCertPaths.CertFile = cert
		exitSpec.ExitCertPaths.KeyFile = key
		data, e := BuildExitXRayJSON(&exitSpec, strategy, "error")
		if e != nil {
			t.Fatal(e)
		}
		var cfg map[string]any
		if e = json.Unmarshal(data, &cfg); e != nil {
			t.Fatal(e)
		}
		// Separate local destinations identify which real exit carried the request.
		cfg["outbounds"].([]any)[0].(map[string]any)["settings"] = map[string]any{"redirect": destination.Listener.Addr().String()}
		exitConfigs[i], e = json.Marshal(cfg)
		if e != nil {
			t.Fatal(e)
		}
		if e = exitRunners[i].StartJSON(exitConfigs[i]); e != nil {
			t.Fatal(e)
		}
		defer func() { _ = exitRunners[i].Close() }()
	}
	primary := nodes[0].ID
	owner := auth.User{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653f0", Kind: "vless", PreferredExitID: &primary, Routes: []auth.RouteCredential{{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653f1", ExitID: &primary, Published: true}}}
	var bridge proxy.Runner
	defer func() { _ = bridge.Close() }()
	selector := exits.NewSelector(func(ctx context.Context, n exits.Node) exits.Health {
		// An IP target avoids external DNS and still exercises full-body checks through each outbound.
		ctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		return bridge.ProbeExit(ctx, n, []string{"http://127.0.0.1:1/check"})
	})
	selector.SetActiveID(primary)
	apply := func() {
		users := auth.ExpandRoutes([]auth.User{owner})
		for i := range users {
			users[i].EffectiveExitID = users[i].SelectExit(nodes, selector.ActiveID(), selector.HealthSnapshot())
		}
		data, e := BuildBridgeXRayJSON(spec, users, nodes, selector.ActiveID(), strategy, "error")
		if e != nil {
			t.Fatal(e)
		}
		if e = bridge.Reload(data); e != nil {
			t.Fatal(e)
		}
	}
	apply()
	clients := make([]*http.Client, 0, 2)
	for _, u := range auth.ExpandRoutes([]auth.User{owner}) {
		export, e := BuildSubscriptionExport(spec, u)
		if e != nil {
			t.Fatal(e)
		}
		data, e := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "error"}, "outbounds": []any{export.XRayOutboundJSON}})
		if e != nil {
			t.Fatal(e)
		}
		client := &proxy.Runner{}
		if e = client.StartJSON(data); e != nil {
			t.Fatal(e)
		}
		defer func() { _ = client.Close() }()
		tr := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d, e := xnet.ParseDestination(network + ":" + addr)
			if e != nil {
				return nil, e
			}
			return core.Dial(ctx, client.Instance(), d)
		}}
		defer tr.CloseIdleConnections()
		clients = append(clients, &http.Client{Transport: tr, Timeout: time.Second})
	}
	check := func(client *http.Client, want byte) {
		t.Helper()
		response, e := client.Get("http://127.0.0.1:1/payload")
		if want == 0 {
			if e == nil {
				_ = response.Body.Close()
				t.Fatal("fixed profile used the reserve")
			}
			return
		}
		if e != nil {
			t.Fatal(e)
		}
		payload, e := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if e != nil || len(payload) != 65536 || payload[0] != want {
			t.Fatalf("payload length=%d, want exit %c, err=%v", len(payload), want, e)
		}
	}
	for range 3 {
		selector.ProbeAndSelect(context.Background(), nodes)
	}
	check(clients[0], 'a')
	check(clients[1], 'a')
	if err = exitRunners[0].Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		selector.ProbeAndSelect(context.Background(), nodes)
	}
	if selector.ActiveID() != "reserve" {
		t.Fatal("no measured failover", selector.HealthSnapshot())
	}
	apply()
	check(clients[0], 'b')
	check(clients[1], 0)
	// Recovery eligibility alone must not move Auto back before the stability window.
	if err = exitRunners[0].StartJSON(exitConfigs[0]); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		selector.ProbeAndSelect(context.Background(), nodes)
	}
	apply()
	check(clients[0], 'b')
	check(clients[1], 'a')
	// The 60-second selection gate is covered with a fake clock in exits/selector_test.go.
	// Verify applying its eventual failback with the same running clients here.
	selector.SetActiveID(primary)
	apply()
	check(clients[0], 'a')
	check(clients[1], 'a')
	owner.ExcludedExitIDs = []string{primary}
	apply()
	check(clients[0], 'b')
	check(clients[1], 0)
}
