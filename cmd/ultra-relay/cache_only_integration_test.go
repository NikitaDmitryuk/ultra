package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/NikitaDmitryuk/ultra/internal/proxy"
	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

// The adapter starts the real core, changing only its unused legacy health
// listener to a fixture port so independent Go test packages cannot collide.
type cacheIntegrationRunner struct {
	*proxy.Runner
	healthPort int
}

func (r *cacheIntegrationRunner) config(raw []byte) ([]byte, error) {
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	for _, item := range cfg["inbounds"].([]any) {
		inbound := item.(map[string]any)
		if inbound["tag"] == config.HealthProbeInboundTag {
			inbound["port"] = r.healthPort
		}
	}
	return json.Marshal(cfg)
}
func (r *cacheIntegrationRunner) ValidateJSON(raw []byte) error {
	data, err := r.config(raw)
	if err != nil {
		return err
	}
	return r.Runner.ValidateJSON(data)
}
func (r *cacheIntegrationRunner) ReloadReason(raw []byte, reason string) error {
	data, err := r.config(raw)
	if err != nil {
		return err
	}
	return r.Runner.ReloadReason(data, reason)
}

func cacheTestPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port
}
func cacheTestCertificate(t *testing.T) (cert, key, pin string) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cache.test"}, DNSNames: []string{"cache.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalECPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cert = filepath.Join(dir, "cert.pem")
	key = filepath.Join(dir, "key.pem")
	if err = os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: raw}), 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return cert, key, hex.EncodeToString(sum[:])
}
func cacheTestExit(t *testing.T, spec *config.Spec, redirect string, strategy mimic.Strategy) *proxy.Runner {
	t.Helper()
	raw, err := config.BuildExitXRayJSON(spec, strategy, "error")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err = json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	// Only these loopback fixtures permit local destinations. Real exit configs
	// retain Xray's protection of private destination addresses.
	cfg["outbounds"] = []any{map[string]any{"protocol": "freedom", "tag": "direct", "settings": map[string]any{"redirect": redirect, "finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.0/8"}}}}}}
	delete(cfg, "routing")
	raw, _ = json.Marshal(cfg)
	runner := new(proxy.Runner)
	if err = runner.StartJSON(raw); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runner.Close() })
	return runner
}
func waitCacheDiagnostics(t *testing.T, spec *config.Spec, token string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", "http://"+spec.AdminListen+"/v1/health", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		hc := &http.Client{Timeout: time.Second}
		response, err := hc.Do(req)
		if err == nil {
			var decoded map[string]any
			err = json.NewDecoder(response.Body).Decode(&decoded)
			_ = response.Body.Close()
			if err == nil && response.StatusCode == 200 {
				return decoded
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("cache-only diagnostics did not start")
	return nil
}
func startCacheBridge(t *testing.T, spec *config.Spec, path, token string, strategy mimic.Strategy) (*proxy.Runner, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	runner := &cacheIntegrationRunner{Runner: new(proxy.Runner), healthPort: cacheTestPort(t)}
	done := make(chan error, 1)
	go func() {
		done <- runBridge(ctx, spec, "unused-spec-path", path, token, runner, strategy, "error", slog.New(slog.NewTextHandler(io.Discard, nil)), bridgeOptions{CacheOnly: true, probeInterval: 100 * time.Millisecond})
	}()
	stop := func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("cache-only shutdown blocked")
		}
	}
	var once sync.Once
	stopOnce := func() { once.Do(stop) }
	t.Cleanup(stopOnce)
	waitCacheDiagnostics(t, spec, token)
	return runner.Runner, stopOnce
}

func TestCacheOnlyRealStartupRestartFailoverAndJournal(t *testing.T) {
	dbSpy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dbSpy.Close() }()
	var databaseConnections atomic.Int64
	go func() {
		for {
			conn, err := dbSpy.Accept()
			if err != nil {
				return
			}
			databaseConnections.Add(1)
			_ = conn.Close()
		}
	}()
	payloadA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, strings.Repeat("a", 65536)) }))
	defer payloadA.Close()
	payloadB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, strings.Repeat("b", 65536)) }))
	defer payloadB.Close()
	cert, key, pin := cacheTestCertificate(t)
	strategy, err := mimic.New("apijson")
	if err != nil {
		t.Fatal(err)
	}
	tunnelUUID := "11111111-2222-3333-4444-555555555555"
	spec := &config.Spec{Role: config.RoleBridge, DevMode: true, ListenAddress: "127.0.0.1", VLESSPort: cacheTestPort(t), AdminListen: fmt.Sprintf("127.0.0.1:%d", cacheTestPort(t)), PublicHost: "127.0.0.1", SplitRouting: config.BoolPtr(false), SplithttpHost: "cache.test", SplitHTTPTLS: config.SplitHTTPTLSSpec{ServerName: "cache.test"}, TunnelTLSProvision: config.TunnelTLSSelfSigned, ProbeURLs: []string{payloadA.URL}, Database: &config.DatabaseSpec{DSN: "postgres://invalid:invalid@" + dbSpy.Addr().String() + "/no_control"}}
	nodes := []exits.Node{{ID: "a", Address: "127.0.0.1", Port: cacheTestPort(t), TunnelUUID: tunnelUUID, PinnedPeerCertSHA256: pin, Priority: 100, Enabled: true}, {ID: "b", Address: "127.0.0.1", Port: cacheTestPort(t), TunnelUUID: tunnelUUID, PinnedPeerCertSHA256: pin, Priority: 200, Enabled: true}}
	makeExit := func(n exits.Node, dest string) *proxy.Runner {
		s := *spec
		s.Role = config.RoleExit
		s.VLESSPort = n.Port
		s.Exit.TunnelUUID = tunnelUUID
		s.ExitCertPaths = config.CertPaths{CertFile: cert, KeyFile: key}
		return cacheTestExit(t, &s, dest, strategy)
	}
	exitA := makeExit(nodes[0], payloadA.Listener.Addr().String())
	_ = makeExit(nodes[1], payloadB.Listener.Addr().String())
	pref := "a"
	owner := auth.User{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee", AccountID: "owner", IsActive: true, Routes: []auth.RouteCredential{{UUID: "3b7d2c48-cc5c-4ae4-b054-2dd59ce9e27b", ExitID: &pref}}}
	now := time.Now().UTC()
	limits := []runtimestate.QuotaLimit{}
	for _, n := range nodes {
		for _, id := range []string{"owner", ""} {
			limits = append(limits, runtimestate.QuotaLimit{AccountID: id, ExitID: n.ID, Period: now.Format("2006-01"), LimitBytes: 8 * 1024 * 1024, ExpiresAt: now.Add(runtimeLease)})
		}
	}
	snapshot := runtimeSnapshotV1{Version: 1, Fingerprint: runtimeFingerprint(spec), Users: snapshotUsers([]auth.User{owner}), Nodes: nodes, Limits: limits}
	raw, _ := json.Marshal(snapshot)
	path := filepath.Join(t.TempDir(), "runtime.db")
	state, err := runtimestate.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = state.SaveSnapshot(runtimestate.Snapshot{Revision: 7, ConfirmedAt: now, Payload: raw}, limits); err != nil {
		t.Fatal(err)
	}
	_ = state.Close()
	token := "test-cache-only-token"
	_, stop := startCacheBridge(t, spec, path, token, strategy)
	stopped := false
	defer func() {
		if !stopped {
			stop()
		}
	}()
	diagnostics := waitCacheDiagnostics(t, spec, token)
	runtime := diagnostics["runtime"].(map[string]any)
	if runtime["mode"] != "cache_only" || runtime["control_disabled"] != true || diagnostics["control_ready"] != false {
		t.Fatal("unexpected emergency diagnostics", runtime)
	}
	clientJSON, _ := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "error"}, "outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": spec.VLESSPort, "users": []any{map[string]any{"id": owner.Routes[0].UUID, "encryption": "none"}}}}}, "streamSettings": map[string]any{"network": "tcp", "security": "none"}}}})
	client := new(proxy.Runner)
	if err = client.StartJSON(clientJSON); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	tr := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		destination, err := xnet.ParseDestination(network + ":" + address)
		if err != nil {
			return nil, err
		}
		return core.Dial(ctx, client.Instance(), destination)
	}}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	fetch := func() (byte, error) {
		response, err := hc.Get(payloadA.URL)
		if err != nil {
			return 0, err
		}
		defer func() { _ = response.Body.Close() }()
		body, err := io.ReadAll(response.Body)
		if err != nil || len(body) != 65536 {
			return 0, fmt.Errorf("payload unavailable: %v size=%d", err, len(body))
		}
		return body[0], nil
	}
	if body, err := fetch(); err != nil || body != 'a' {
		t.Fatalf("cached initial route: %q %v", body, err)
	}
	if err = exitA.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(8 * time.Second)
	switched := false
	for time.Now().Before(deadline) {
		if body, err := fetch(); err == nil && body == 'b' {
			switched = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !switched {
		t.Fatal("real cached failover did not recover data through backup exit")
	}
	stop()
	stopped = true
	state, err = runtimestate.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := state.LoadSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !saved.ConfirmedAt.Equal(now) || saved.Revision != 7 {
		t.Fatal("cache-only refreshed confirmation")
	}
	count, _, _, err := state.PendingStats()
	if err != nil || count == 0 {
		t.Fatal("real traffic did not survive in durable journal", count, err)
	}
	leftBefore, err := state.Remaining("owner", "b")
	if err != nil {
		t.Fatal(err)
	}
	_ = state.Close()
	_, stop = startCacheBridge(t, spec, path, token, strategy)
	stopped = false
	deadline = time.Now().Add(8 * time.Second)
	switched = false
	for time.Now().Before(deadline) {
		if body, err := fetch(); err == nil && body == 'b' {
			switched = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !switched {
		t.Fatal("real restarted cache-only VPN did not recover")
	}
	stop()
	stopped = true
	state, err = runtimestate.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func(s *runtimestate.Store) { _ = s.Close() }(state)
	leftAfter, err := state.Remaining("owner", "b")
	if err != nil || leftAfter >= leftBefore {
		t.Fatal("restart refunded or bypassed durable reservation", leftBefore, leftAfter, err)
	}
	saved, err = state.LoadSnapshot()
	if err != nil || !saved.ConfirmedAt.Equal(now) {
		t.Fatal("restart extended cache lease")
	}
	if databaseConnections.Load() != 0 {
		t.Fatal("cache-only attempted a database connection", databaseConnections.Load())
	}
	// Rehearse a running authorization reaching its absolute deadline. Restart
	// must not convert that deadline into a fresh lease or keep sockets alive.
	short := saved
	short.ConfirmedAt = time.Now().UTC().Add(-runtimeLease + 1500*time.Millisecond)
	if err = state.RestoreSnapshot(&short, limits); err != nil {
		t.Fatal(err)
	}
	_ = state.Close()
	bridge, stop := startCacheBridge(t, spec, path, token, strategy)
	stopped = false
	if bridge.Instance() == nil {
		t.Fatal("short valid cached lease did not start a real core")
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && bridge.Instance() != nil {
		time.Sleep(50 * time.Millisecond)
	}
	if bridge.Instance() != nil {
		t.Fatal("running cache-only core outlived its absolute lease")
	}
	diagnostics = waitCacheDiagnostics(t, spec, token)
	if diagnostics["runtime"].(map[string]any)["mode"] != "closed" {
		t.Fatal("expired running cache mode not diagnosed closed")
	}
	if _, err := fetch(); err == nil {
		t.Fatal("expired cache-only VPN still transmitted data")
	}
	stop()
	stopped = true
	state, err = runtimestate.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func(s *runtimestate.Store) { _ = s.Close() }(state)
	saved, err = state.LoadSnapshot()
	if err != nil || !saved.ConfirmedAt.Equal(short.ConfirmedAt) {
		t.Fatal("expired running cache lease was extended")
	}
}

func TestCacheOnlyBadStateKeepsOnlyAuthenticatedDiagnostics(t *testing.T) {
	for _, kind := range []string{"missing", "empty", "corrupt", "expired", "incompatible", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			spec := &config.Spec{Role: config.RoleBridge, DevMode: true, ListenAddress: "127.0.0.1", VLESSPort: cacheTestPort(t), AdminListen: fmt.Sprintf("127.0.0.1:%d", cacheTestPort(t)), SplitRouting: config.BoolPtr(false), Database: &config.DatabaseSpec{DSN: "postgres://invalid:invalid@127.0.0.1:1/no_control"}}
			path := filepath.Join(t.TempDir(), "runtime.db")
			now := time.Now().UTC()
			switch kind {
			case "empty":
				if err := os.WriteFile(path, nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(path, []byte(strings.Repeat("x", 8192)), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(t.TempDir(), "other")
				if err := os.WriteFile(target, []byte(strings.Repeat("x", 8192)), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "expired", "incompatible":
				state, err := runtimestate.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				p := runtimeSnapshotV1{Version: 1, Fingerprint: runtimeFingerprint(spec)}
				confirmed := now
				if kind == "expired" {
					confirmed = now.Add(-25 * time.Hour)
				} else {
					p.Fingerprint = "another deployment"
				}
				raw, _ := json.Marshal(p)
				if err := state.SaveSnapshot(runtimestate.Snapshot{Revision: 3, ConfirmedAt: confirmed, Payload: raw}, nil); err != nil {
					t.Fatal(err)
				}
				_ = state.Close()
			}
			strategy, err := mimic.New("apijson")
			if err != nil {
				t.Fatal(err)
			}
			runner, stop := startCacheBridge(t, spec, path, "cache-test", strategy)
			diag := waitCacheDiagnostics(t, spec, "cache-test")
			runtime := diag["runtime"].(map[string]any)
			if runtime["mode"] != "closed" || runtime["control_disabled"] != true || runner.Instance() != nil {
				t.Fatal("unusable state allowed a dataplane", runtime)
			}
			hc := &http.Client{Timeout: time.Second}
			response, err := hc.Get("http://" + spec.AdminListen + "/v1/health")
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != http.StatusUnauthorized {
				t.Fatal("anonymous emergency diagnostics exposed")
			}
			req, _ := http.NewRequest("POST", "http://"+spec.AdminListen+"/v1/users", strings.NewReader(`{}`))
			req.Header.Set("Authorization", "Bearer cache-test")
			response, err = hc.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != http.StatusServiceUnavailable {
				t.Fatal("cache-only control mutation accepted")
			}
			stop()
			if kind == "missing" {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("missing emergency journal recreated")
				}
			}
			if kind == "empty" {
				info, err := os.Stat(path)
				if err != nil || info.Size() != 0 {
					t.Fatal("empty emergency journal recreated")
				}
			}
		})
	}
}
