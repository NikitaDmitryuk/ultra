package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/NikitaDmitryuk/ultra/internal/proxy"
	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
)

// acceptanceGate owns only this test's streams, never the shared exit listener.
type acceptanceGate struct {
	mu          sync.Mutex
	listener    net.Listener
	target      string
	enabled     bool
	streams     map[net.Conn]bool
	dialSuccess uint64
	dialFailure uint64
}

func newAcceptanceGate(t *testing.T, target string) *acceptanceGate {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("fixture listener unavailable")
	}
	g := &acceptanceGate{listener: l, target: target, enabled: true, streams: map[net.Conn]bool{}}
	t.Cleanup(func() { _ = l.Close(); g.set(false) })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go g.forward(c)
		}
	}()
	return g
}
func (g *acceptanceGate) forward(c net.Conn) {
	g.mu.Lock()
	if !g.enabled {
		g.mu.Unlock()
		_ = c.Close()
		return
	}
	g.streams[c] = true
	g.mu.Unlock()
	defer func() { g.mu.Lock(); delete(g.streams, c); g.mu.Unlock(); _ = c.Close() }()
	upstream, err := net.DialTimeout("tcp", g.target, 3*time.Second)
	g.mu.Lock()
	if err != nil {
		g.dialFailure++
	} else {
		g.dialSuccess++
	}
	g.mu.Unlock()
	if err != nil {
		return
	}
	defer func() { g.mu.Lock(); delete(g.streams, upstream); g.mu.Unlock(); _ = upstream.Close() }()
	g.mu.Lock()
	if !g.enabled {
		g.mu.Unlock()
		return
	}
	g.streams[upstream] = true
	g.mu.Unlock()
	done := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(upstream, c)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	_, _ = io.Copy(c, upstream)
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	_ = c.Close()
	_ = upstream.Close()
	<-done
}
func (g *acceptanceGate) set(enabled bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.enabled = enabled
	if !enabled {
		for c := range g.streams {
			_ = c.Close()
		}
	}
}

// Only bounded non-identifying health fields reach the acceptance log.
type acceptanceRunner struct {
	*cacheIntegrationRunner
	healthMu sync.Mutex
	health   map[string]exits.Health
}

func (r *acceptanceRunner) ProbeExit(ctx context.Context, n exits.Node, targets []string) exits.Health {
	h := r.Runner.ProbeExit(ctx, n, targets)
	r.healthMu.Lock()
	r.health[n.ID] = h
	r.healthMu.Unlock()
	return h
}
func (r *acceptanceRunner) diagnostics(t *testing.T, nodes []exits.Node) {
	t.Helper()
	r.healthMu.Lock()
	defer r.healthMu.Unlock()
	for i, n := range nodes {
		h := r.health[n.ID]
		type check struct {
			OK         bool
			Bytes      int64
			DurationMS int64
			Error      string
		}
		checks := []check{}
		for _, c := range h.Checks {
			checks = append(checks, check{c.OK, c.Bytes, c.DurationMS, c.Error})
		}
		raw, _ := json.Marshal(checks)
		t.Logf("isolated exit[%d]: gate_reachable=%t payload_health=%t checks=%s", i, h.Reachable, h.InternetOK, raw)
	}
	status := r.Status()
	t.Logf("isolated reload_count=%d reload_error=%t", status.Count, status.Error != "")
}

func acceptanceTransportJSON(spec *config.Spec, nodes []exits.Node) ([]byte, error) {
	strategy, err := mimic.New(spec.MimicPreset)
	if err != nil {
		return nil, err
	}
	raw, err := config.BuildBridgeXRayJSON(spec, nil, nodes, nodes[0].ID, strategy, "none")
	if err != nil {
		return nil, err
	}
	var value struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err = json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	var selected []map[string]any
	for _, out := range value.Outbounds {
		for _, node := range nodes {
			if out["tag"] == exits.OutboundTag(node.ID) {
				selected = append(selected, out)
			}
		}
	}
	return json.Marshal(selected)
}

func TestAcceptanceTransportComparisonDetectsWrongMimic(t *testing.T) {
	spec := &config.Spec{Role: config.RoleBridge, MimicPreset: "steamlike", PublicHost: "127.0.0.1", VLESSPort: 443, SplitRouting: config.BoolPtr(false), SplithttpPath: "/fixture"}
	nodes := []exits.Node{{ID: "fixture", Address: "127.0.0.1", Port: 8443, TunnelUUID: "fixture", Enabled: true}}
	before, err := acceptanceTransportJSON(spec, nodes)
	if err != nil {
		t.Fatal(err)
	}
	isolated := *spec
	isolated.DevMode = true
	after, err := acceptanceTransportJSON(&isolated, nodes)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("isolated inbound changed outbound transport")
	}
	isolated.MimicPreset = "apijson"
	after, err = acceptanceTransportJSON(&isolated, nodes)
	if err != nil || bytes.Equal(before, after) {
		t.Fatal("preset mismatch not detected")
	}
	isolated = *spec
	isolated.XrayWire = &config.XrayWireSpec{SplithttpMode: "stream-one"}
	after, err = acceptanceTransportJSON(&isolated, nodes)
	if err != nil || bytes.Equal(before, after) {
		t.Fatal("wire mode mismatch not detected")
	}
}

// Explicit opt-in keeps a production-cadence acceptance out of ordinary suites.
// A live fixture contains only tunnel parameters, two exit credentials and the
// expected egress IPs. It must never contain a production runtime journal.
func TestExitAcceptanceProductionCadence(t *testing.T) {
	livePath := os.Getenv("ULTRA_LIVE_EXIT_FIXTURE")
	if livePath == "" && os.Getenv("ULTRA_EXIT_ACCEPTANCE_LOCAL") != "1" {
		t.Skip("explicit isolated exit acceptance required")
	}
	var fixture struct {
		Tunnel     config.Spec  `json:"tunnel"`
		Nodes      []exits.Node `json:"nodes"`
		PayloadURL string       `json:"payload_url"`
		Expected   []string     `json:"expected"`
	}
	strategy, _ := mimic.New("apijson")
	spec := &config.Spec{Role: config.RoleBridge, DevMode: true, ListenAddress: "127.0.0.1", PublicHost: "127.0.0.1", VLESSPort: cacheTestPort(t), AdminListen: fmt.Sprintf("127.0.0.1:%d", cacheTestPort(t)), SplitRouting: config.BoolPtr(false), Database: &config.DatabaseSpec{DSN: "postgres://invalid:invalid@127.0.0.1:1/isolated_no_control"}}
	if livePath != "" {
		info, err := os.Lstat(livePath)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 65536 {
			t.Fatal("private bounded fixture required")
		}
		raw, err := os.ReadFile(livePath)
		if err != nil || json.Unmarshal(raw, &fixture) != nil {
			t.Fatal("invalid private fixture")
		}
		if len(fixture.Nodes) != 2 || len(fixture.Expected) != 2 || !strings.HasPrefix(fixture.PayloadURL, "https://") {
			t.Fatal("two exits and HTTPS payload required")
		}
		for i, n := range fixture.Nodes {
			if net.ParseIP(n.Address) == nil || n.Port < 1 || n.Port > 65535 || n.TunnelUUID == "" || n.PinnedPeerCertSHA256 == "" || net.ParseIP(fixture.Expected[i]) == nil {
				t.Fatal("invalid tunnel fixture")
			}
		}
		// Whitelist transport settings; database, users, listeners and workers cannot be inherited.
		spec.MimicPreset = fixture.Tunnel.MimicPreset
		spec.XrayWire = fixture.Tunnel.XrayWire
		strategy, err = mimic.New(spec.MimicPreset)
		if err != nil {
			t.Fatal("fixture transport preset unavailable")
		}
		spec.SplitHTTPTLS = fixture.Tunnel.SplitHTTPTLS
		spec.SplithttpPath = fixture.Tunnel.SplithttpPath
		spec.SplithttpHost = fixture.Tunnel.SplithttpHost
		spec.TunnelTransport = fixture.Tunnel.TunnelTransport
		spec.TunnelTLSProvision = fixture.Tunnel.TunnelTLSProvision
		spec.AntiCensor = fixture.Tunnel.AntiCensor
		spec.ProbeURLs = fixture.Tunnel.ProbeURLs
		if spec.AntiCensor != nil {
			copy := *spec.AntiCensor
			copy.PublicXHTTPPort = 0
			spec.AntiCensor = &copy
		}
	} else {
		cert, key, pin := cacheTestCertificate(t)
		spec.SplithttpHost = "cache.test"
		spec.SplitHTTPTLS = config.SplitHTTPTLSSpec{ServerName: "cache.test"}
		spec.TunnelTLSProvision = config.TunnelTLSSelfSigned
		fixture.Expected = []string{"127.0.0.2", "127.0.0.3"}
		for i, expected := range fixture.Expected {
			body := fmt.Sprintf(`{"ip":%q}`, expected)
			body += strings.Repeat(" ", 65536-len(body))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }))
			t.Cleanup(server.Close)
			if i == 0 {
				fixture.PayloadURL = server.URL
				spec.ProbeURLs = []string{server.URL}
			}
			node := exits.Node{ID: fmt.Sprintf("acceptance-%d", i), Address: "127.0.0.1", Port: cacheTestPort(t), TunnelUUID: "11111111-2222-3333-4444-555555555555", PinnedPeerCertSHA256: pin, Priority: 100 + i, Enabled: true}
			exitSpec := *spec
			exitSpec.Role = config.RoleExit
			exitSpec.VLESSPort = node.Port
			exitSpec.Exit.TunnelUUID = node.TunnelUUID
			exitSpec.ExitCertPaths = config.CertPaths{CertFile: cert, KeyFile: key}
			cacheTestExit(t, &exitSpec, server.Listener.Addr().String(), strategy)
			fixture.Nodes = append(fixture.Nodes, node)
		}
	}
	if livePath != "" {
		reference := fixture.Tunnel
		reference.Role = config.RoleBridge
		reference.PublicHost = spec.PublicHost
		reference.VLESSPort = spec.VLESSPort
		reference.SplitRouting = config.BoolPtr(false)
		if reference.SplithttpPath == "" {
			t.Fatal("explicit stable tunnel path required for live comparison")
		}
		expected, err := acceptanceTransportJSON(&reference, fixture.Nodes)
		if err != nil {
			t.Fatal("reference tunnel configuration unavailable")
		}
		actual, err := acceptanceTransportJSON(spec, fixture.Nodes)
		if err != nil || !bytes.Equal(expected, actual) {
			t.Fatal("isolated outbound transport differs from source")
		}
		t.Log("isolated outbound settings match source before loopback gate substitution")
	}
	gates := make([]*acceptanceGate, 2)
	for i := range fixture.Nodes {
		n := &fixture.Nodes[i]
		gates[i] = newAcceptanceGate(t, n.DialAddr())
		n.Address = "127.0.0.1"
		n.Port = gates[i].listener.Addr().(*net.TCPAddr).Port
		n.Priority = 100 + i
		n.Enabled = true
	}
	pref := fixture.Nodes[0].ID
	owner := auth.User{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee", AccountID: "isolated-acceptance", IsActive: true, Routes: []auth.RouteCredential{{UUID: "3b7d2c48-cc5c-4ae4-b054-2dd59ce9e27b", ExitID: &pref}}}
	now := time.Now().UTC()
	var limits []runtimestate.QuotaLimit
	for _, n := range fixture.Nodes {
		for _, account := range []string{owner.AccountID, ""} {
			limits = append(limits, runtimestate.QuotaLimit{AccountID: account, ExitID: n.ID, Period: now.Format("2006-01"), LimitBytes: 32 << 20, ExpiresAt: now.Add(time.Hour)})
		}
	}
	raw, _ := json.Marshal(runtimeSnapshotV1{Version: 1, Fingerprint: runtimeFingerprint(spec), Users: snapshotUsers([]auth.User{owner}), Nodes: fixture.Nodes, Limits: limits})
	statePath := filepath.Join(t.TempDir(), "runtime.db")
	state, err := runtimestate.Open(statePath)
	if err != nil {
		t.Fatal("fixture state unavailable")
	}
	if err = state.SaveSnapshot(runtimestate.Snapshot{Revision: 1, ConfirmedAt: now, Payload: raw}, limits); err != nil {
		_ = state.Close()
		t.Fatal("fixture snapshot unavailable")
	}
	_ = state.Close()
	runner := &acceptanceRunner{cacheIntegrationRunner: &cacheIntegrationRunner{Runner: new(proxy.Runner), healthPort: cacheTestPort(t)}, health: map[string]exits.Health{}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runBridge(ctx, spec, "unused", statePath, "isolated-test-token", runner, strategy, "none", slog.New(slog.NewTextHandler(io.Discard, nil)), bridgeOptions{CacheOnly: true})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error("isolated bridge failed")
			}
		case <-time.After(10 * time.Second):
			t.Error("isolated bridge cleanup timed out")
		}
	})
	waitCacheDiagnostics(t, spec, "isolated-test-token")
	clientJSON, _ := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "none"}, "outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": spec.VLESSPort, "users": []any{map[string]any{"id": owner.Routes[0].UUID, "encryption": "none"}}}}}, "streamSettings": map[string]any{"network": "tcp", "security": "none"}}}})
	client := new(proxy.Runner)
	if client.StartJSON(clientJSON) != nil {
		t.Fatal("isolated client failed")
	}
	t.Cleanup(func() { _ = client.Close() })
	tr := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		dest, err := xnet.ParseDestination(network + ":" + address)
		if err != nil {
			return nil, err
		}
		return core.Dial(ctx, client.Instance(), dest)
	}}
	t.Cleanup(tr.CloseIdleConnections)
	hc := &http.Client{Transport: tr, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	fetchWithClient := func(hc *http.Client) (string, error) {
		r, e := hc.Get(fixture.PayloadURL)
		if e != nil {
			return "", fmt.Errorf("payload unavailable")
		}
		defer func() { _ = r.Body.Close() }()
		b, e := io.ReadAll(io.LimitReader(r.Body, 65537))
		if e != nil || r.StatusCode != 200 {
			return "", fmt.Errorf("payload unavailable")
		}
		var v struct {
			IP string `json:"ip"`
		}
		if json.Unmarshal(b, &v) == nil && v.IP != "" {
			return v.IP, nil
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "ip=") {
				return strings.TrimPrefix(line, "ip="), nil
			}
		}
		return "", fmt.Errorf("invalid egress response")
	}
	fetch := func() (string, error) { return fetchWithClient(hc) }
	t.Cleanup(func() {
		if t.Failed() {
			for i, gate := range gates {
				gate.mu.Lock()
				t.Logf("isolated gate[%d]: upstream_dial_success=%d upstream_dial_failure=%d", i, gate.dialSuccess, gate.dialFailure)
				gate.mu.Unlock()
			}
			runner.diagnostics(t, fixture.Nodes)
		}
	})
	// Establish real payload reachability through each exact generated outbound
	// before attributing later failure to route selection.
	for i, n := range fixture.Nodes {
		preflightTransport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dest, err := xnet.ParseDestination(network + ":" + address)
			if err != nil {
				return nil, err
			}
			ctx = session.ContextWithContent(ctx, &session.Content{SkipDNSResolve: true})
			ctx = session.SetForcedOutboundTagToContext(ctx, exits.OutboundTag(n.ID))
			return core.Dial(ctx, runner.Instance(), dest)
		}}
		directClient := &http.Client{Transport: preflightTransport, Timeout: 8 * time.Second, CheckRedirect: hc.CheckRedirect}
		ip, err := fetchWithClient(directClient)
		preflightTransport.CloseIdleConnections()
		h := runner.ProbeExit(context.Background(), n, spec.HealthTargets())
		if err != nil {
			t.Fatalf("preflight exit[%d] tunnel payload unavailable (health=%t)", i, h.InternetOK)
		}
		if net.ParseIP(ip) == nil {
			t.Fatal("preflight invalid egress response")
		}
		if ip != fixture.Expected[i] {
			t.Fatalf("preflight exit[%d] unexpected egress: %s", i, ip)
		}
		t.Logf("preflight exit[%d] tunnel egress confirmed, health=%t", i, h.InternetOK)
	}
	runner.diagnostics(t, fixture.Nodes)
	await := func(label, want string, deadline time.Duration) {
		t.Helper()
		start := time.Now()
		for time.Since(start) < deadline {
			ip, e := fetch()
			if e == nil {
				if ip != fixture.Expected[0] && ip != fixture.Expected[1] {
					if net.ParseIP(ip) == nil {
						t.Fatal("invalid egress response")
					}
					t.Fatalf("unexpected egress outside allowed exits: %s", ip)
				}
				if ip == want {
					t.Logf("%s recovered after %s (production 10s probes)", label, time.Since(start).Round(time.Millisecond))
					return
				}
			}
			time.Sleep(time.Second)
		}
		t.Fatalf("%s did not recover within %s", label, deadline)
	}
	await("initial primary", fixture.Expected[0], 15*time.Second)
	gates[0].set(false)
	await("primary failure to reserve", fixture.Expected[1], 60*time.Second)
	if livePath != "" {
		restored := time.Now()
		gates[0].set(true)
		for time.Since(restored) < 59*time.Second {
			ip, e := fetch()
			if e == nil && ip != fixture.Expected[1] {
				t.Fatal("preferred return before 60s stability")
			}
			time.Sleep(time.Second)
		}
		await("stable preferred return", fixture.Expected[0], 40*time.Second)
		gates[0].set(false)
		await("reserve before reverse failure", fixture.Expected[1], 60*time.Second)
		gates[0].set(true)
		gates[1].set(false)
		await("reserve failure to recovered primary", fixture.Expected[0], 60*time.Second)
	}
	gates[0].set(false)
	gates[1].set(false)
	start := time.Now()
	for time.Since(start) < 5*time.Second {
		if _, e := fetch(); e == nil {
			t.Fatal("payload passed while both isolated paths down")
		}
	}
	t.Log("both isolated paths down: new payloads blocked")
}
