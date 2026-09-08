package config

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
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

func TestQuotaWithoutFallbackBlocksActualTransfer(t *testing.T) {
	var requests atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(http.StatusOK) }))
	defer destination.Close()
	pref := "atl"
	user := auth.User{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee", PreferredExitID: &pref, FallbackExitID: "ams", ExcludedExitIDs: []string{"atl"}}
	user.EffectiveExitID = user.SelectExit([]exits.Node{{ID: "atl"}, {ID: "ams"}}, "atl", map[string]exits.Health{"atl": {Eligible: true, PreferredReady: true}, "ams": {}})
	if user.EffectiveExitID != auth.BlockedExit {
		t.Fatal("missing fallback did not block")
	}
	spec := &Spec{Role: RoleBridge, ListenAddress: "127.0.0.1", PublicHost: "127.0.0.1", VLESSPort: freePort(t), DevMode: true, SplitRouting: BoolPtr(false), Exit: ExitTunnelSpec{Address: "127.0.0.1", Port: freePort(t), TunnelUUID: user.UUID}}
	strategy, err := mimic.New("apijson")
	if err != nil {
		t.Fatal(err)
	}
	data, err := BuildBridgeXRayJSON(spec, []auth.User{user}, nil, "", strategy, "error")
	if err != nil {
		t.Fatal(err)
	}
	var relay proxy.Runner
	if err = relay.StartJSON(data); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = relay.Close() }()
	export, err := BuildClientExport(spec, user)
	if err != nil {
		t.Fatal(err)
	}
	clientData, err := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "error"}, "outbounds": []any{export.XRayOutboundJSON}})
	if err != nil {
		t.Fatal(err)
	}
	var client proxy.Runner
	if err = client.StartJSON(clientData); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	transport := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		d, e := xnet.ParseDestination(network + ":" + addr)
		if e != nil {
			return nil, e
		}
		return core.Dial(ctx, client.Instance(), d)
	}}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Get(destination.URL)
	if err == nil {
		_ = response.Body.Close()
		t.Fatal("blocked user reached destination")
	}
	if requests.Load() != 0 {
		t.Fatal("VPN traffic escaped directly")
	}
}
