package config

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/NikitaDmitryuk/ultra/internal/proxy"
	"github.com/NikitaDmitryuk/ultra/internal/realitykey"
	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
	"github.com/google/uuid"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The pinned REALITY implementation accepts X25519 or X25519MLKEM768 target
// ServerHello shares. Keep the camouflage endpoint independent of Go's evolving
// default groups; these tests exercise accounting, not target compatibility.
func accountingCamouflageTLS() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}
}

func TestAccountingCamouflageNegotiatesRealityCompatibleTLS(t *testing.T) {
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	target.EnableHTTP2 = true
	target.TLS = accountingCamouflageTLS()
	target.StartTLS()
	defer target.Close()
	response, err := target.Client().Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.TLS == nil || response.TLS.Version != tls.VersionTLS13 || response.TLS.CurveID != tls.X25519 {
		t.Fatal("camouflage endpoint negotiated a TLS handshake unsupported by pinned REALITY")
	}
}

func accountingFixture(t *testing.T, capacity int64, udp, direct bool) (*proxy.Runner, *proxy.Runner, *runtimestate.Store, auth.User) {
	t.Helper()
	camouflage := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	camouflage.EnableHTTP2 = true
	camouflage.TLS = accountingCamouflageTLS()
	camouflage.StartTLS()
	t.Cleanup(camouflage.Close)
	keys, e := realitykey.Generate()
	if e != nil {
		t.Fatal(e)
	}
	user := auth.User{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee", AccountID: uuid.NewString(), Kind: "vless", IsActive: true}
	spec := bridgeSpecForAntiCensorTest()
	spec.DevMode = false
	spec.SplitRouting = BoolPtr(false)
	spec.PublicHost = "127.0.0.1"
	spec.ListenAddress = "127.0.0.1"
	spec.VLESSPort = freePort(t)
	spec.AntiCensor = &AntiCensorSpec{PublicXHTTPPort: freePort(t)}
	cert, key := testCertificate(t)
	spec.PublicXHTTPTLS = &PublicXHTTPTLSSpec{Port: freePort(t), ServerName: "example.com", CertificateFile: cert, KeyFile: key, Path: "/test", Mode: "stream-up"}
	spec.Reality = RealitySpec{PrivateKey: keys.PrivateKey, PublicKey: keys.PublicKey, Dest: camouflage.Listener.Addr().String(), ServerNames: []string{"example.com"}}
	strategy, e := mimic.New("steamlike")
	if e != nil {
		t.Fatal(e)
	}
	raw, e := BuildBridgeXRayJSON(spec, []auth.User{user}, nil, "", strategy, "error")
	if e != nil {
		t.Fatal(e)
	}
	var cfg map[string]any
	if e = json.Unmarshal(raw, &cfg); e != nil {
		t.Fatal(e)
	}
	cfg["log"] = map[string]any{"loglevel": "error"}
	cfg["inbounds"] = cfg["inbounds"].([]any)[:3]
	tag := "to-exit-fixture"
	if direct {
		tag = "direct"
	}
	cfg["outbounds"] = []any{map[string]any{"protocol": "freedom", "tag": tag, "settings": map[string]any{"domainStrategy": "UseIP", "finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.0/8"}}}}}}
	delete(cfg, "routing")
	cfg["dns"] = map[string]any{"hosts": map[string]any{"example.com": "127.0.0.1"}}
	raw, e = json.Marshal(cfg)
	if e != nil {
		t.Fatal(e)
	}
	state, e := runtimestate.Open(filepath.Join(t.TempDir(), "runtime.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = state.Close() })
	now := time.Now().UTC()
	q := []runtimestate.QuotaLimit{{AccountID: user.AccountID, ExitID: "fixture", Period: now.Format("2006-01"), LimitBytes: capacity, ExpiresAt: now.Add(time.Hour)}, {ExitID: "fixture", Period: now.Format("2006-01"), LimitBytes: capacity, ExpiresAt: now.Add(time.Hour)}}
	if e = state.SaveSnapshot(runtimestate.Snapshot{ConfirmedAt: now, Payload: []byte(`{}`)}, q); e != nil {
		t.Fatal(e)
	}
	server := &proxy.Runner{}
	if e = server.ConfigureAccounting(state, []auth.User{user}); e != nil {
		t.Fatal(e)
	}
	if e = server.StartJSON(raw); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = server.Close() })
	for _, port := range []int{spec.VLESSPort, spec.AntiCensor.PublicXHTTPPort, spec.PublicXHTTPTLS.Port} {
		c, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), time.Second)
		if e != nil {
			t.Fatal(e)
		}
		_ = c.Close()
	}
	export, e := BuildClientExport(spec, user)
	if e != nil {
		t.Fatal(e)
	}
	if udp {
		outUsers := export.XRayOutboundJSON["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)
		delete(outUsers[0].(map[string]any), "flow")
	}
	raw, e = json.Marshal(map[string]any{"log": map[string]any{"loglevel": "error"}, "outbounds": []any{export.XRayOutboundJSON}})
	if e != nil {
		t.Fatal(e)
	}
	client := &proxy.Runner{}
	if e = client.StartJSON(raw); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = client.Close() })
	return server, client, state, user
}
func TestVisionTLS13ConcurrentQuotaActualTransfer(t *testing.T) {
	const capacity = 1024 * 1024
	server, client, state, user := accountingFixture(t, capacity, false, false)
	destination := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		size := 65536
		if r.URL.Path == "/large" {
			size = 4 * 1024 * 1024
		}
		_, _ = io.WriteString(w, strings.Repeat("x", size))
	}))
	destination.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	destination.StartTLS()
	defer destination.Close()
	roots := x509.NewCertPool()
	roots.AddCert(destination.Certificate())
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS13}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		dest, e := xnet.ParseDestination(network + ":" + addr)
		if e != nil {
			return nil, e
		}
		return core.Dial(ctx, client.Instance(), dest)
	}}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	var wg sync.WaitGroup
	failures := make(chan error, 5)
	for range 5 {
		wg.Go(func() {
			resp, e := hc.Get(destination.URL)
			if e != nil {
				failures <- e
				return
			}
			defer func() { _ = resp.Body.Close() }()
			body, e := io.ReadAll(resp.Body)
			if e != nil || len(body) != 65536 {
				failures <- fmt.Errorf("TLS13 payload %d: %v", len(body), e)
			}
		})
	}
	wg.Wait()
	close(failures)
	for e := range failures {
		t.Error(e)
	}
	if t.Failed() {
		return
	}
	resp, e := hc.Get(destination.URL + "/large")
	if e == nil {
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr == nil || len(body) >= 4*1024*1024 {
			t.Fatalf("Vision bypassed limiter: bytes=%d err=%v", len(body), readErr)
		}
	}
	left, e := state.Remaining(user.AccountID, "fixture")
	if e != nil || left != 0 {
		t.Fatalf("expected quota exhaustion: %d %v", left, e)
	}
	values := server.DrainRouteTraffic()
	n := values[user.AccountID]["to-exit-fixture"]
	if n[0]+n[1] > capacity || n[1] < 5*65536 {
		t.Fatalf("actual accounting lost or overspent %v", n)
	}
}
func TestUDPQuotaActualTransfer(t *testing.T) {
	const capacity = 8192
	server, client, state, user := accountingFixture(t, capacity, true, false)
	listener, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		packet := make([]byte, 2048)
		for {
			n, addr, e := listener.ReadFrom(packet)
			if e != nil {
				return
			}
			_, _ = listener.WriteTo(packet[:n], addr)
		}
	}()
	dest, e := xnet.ParseDestination("udp:" + listener.LocalAddr().String())
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, e := core.Dial(ctx, client.Instance(), dest)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = conn.Close() }()
	success := 0
	payload := []byte(strings.Repeat("u", 1024))
	for range 10 {
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if _, e = conn.Write(payload); e != nil {
			break
		}
		reply := make([]byte, 1024)
		if _, e = io.ReadFull(conn, reply); e != nil {
			break
		}
		if string(reply) != string(payload) {
			t.Fatal("UDP payload changed")
		}
		success++
	}
	if success == 0 {
		t.Fatal("UDP never transmitted")
	}
	if success >= 10 {
		t.Fatal("UDP bypassed quota")
	}
	left, e := state.Remaining(user.AccountID, "fixture")
	if e != nil || left != 0 {
		t.Fatalf("quota %d %v", left, e)
	}
	n := server.DrainRouteTraffic()[user.AccountID]["to-exit-fixture"]
	if n[0]+n[1] > capacity {
		t.Fatalf("UDP exceeded allowance %v", n)
	}
}

func TestBridgeDirectKeepsExitQuotaAndHonorsAuthorization(t *testing.T) {
	server, client, state, user := accountingFixture(t, 8192, false, true)
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, strings.Repeat("d", 65536)) }))
	defer destination.Close()
	tr := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		dest, e := xnet.ParseDestination(network + ":" + addr)
		if e != nil {
			return nil, e
		}
		return core.Dial(ctx, client.Instance(), dest)
	}}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	resp, e := hc.Get(destination.URL)
	if e != nil {
		t.Fatal(e)
	}
	body, e := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if e != nil || len(body) != 65536 {
		t.Fatalf("bridge direct broken %d %v", len(body), e)
	}
	left, e := state.Remaining(user.AccountID, "fixture")
	if e != nil || left != 8192 {
		t.Fatalf("direct consumed exit quota %d %v", left, e)
	}
	n := server.DrainRouteTraffic()[user.AccountID]["direct"]
	if n[1] < 65536 {
		t.Fatalf("direct not measured %v", n)
	}
	snapshot, e := state.LoadSnapshot()
	if e != nil {
		t.Fatal(e)
	}
	snapshot.ConfirmedAt = time.Now().Add(-25 * time.Hour)
	now := time.Now().UTC()
	limits := []runtimestate.QuotaLimit{{AccountID: user.AccountID, ExitID: "fixture", Period: now.Format("2006-01"), LimitBytes: 8192, ExpiresAt: now.Add(time.Hour)}, {ExitID: "fixture", Period: now.Format("2006-01"), LimitBytes: 8192, ExpiresAt: now.Add(time.Hour)}}
	if e = state.RestoreSnapshot(&snapshot, limits); e != nil {
		t.Fatal(e)
	}
	if resp, e = hc.Get(destination.URL); e == nil {
		_, e = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if e == nil {
			t.Fatal("direct bypassed expired authorization")
		}
	}
}
