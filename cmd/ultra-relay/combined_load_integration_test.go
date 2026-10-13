package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/NikitaDmitryuk/ultra/internal/proxy"
	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
	"github.com/NikitaDmitryuk/ultra/internal/stats"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

var errLoadLostAck = errors.New("simulated successful commit with lost response")

type loadTrafficReceiver struct {
	*db.TrafficRepo
	ambiguous atomic.Bool
	calls     atomic.Int64
}

func (r *loadTrafficReceiver) RecordBatch(ctx context.Context, b runtimestate.TrafficBatch) error {
	if err := r.TrafficRepo.RecordBatch(ctx, b); err != nil {
		return err
	}
	r.calls.Add(1)
	if r.ambiguous.CompareAndSwap(false, true) {
		return errLoadLostAck
	}
	return nil
}

type loadRuntimeRunner struct {
	*cacheIntegrationRunner
	state chan *runtimestate.Store
}

func (r *loadRuntimeRunner) ConfigureAccounting(s *runtimestate.Store, users []auth.User) error {
	select {
	case r.state <- s:
	default:
	}
	return r.Runner.ConfigureAccounting(s, users)
}
func loadDatabase(t *testing.T) *db.DB {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("combined load requires explicitly allocated PostgreSQL16 DATABASE_URL")
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "localhost" {
		t.Fatal("combined fixture requires isolated loopback PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "ultra_combined_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		_ = admin.Close(context.Background())
		t.Fatal(err)
	}
	q := parsed.Query()
	q.Set("search_path", schema)
	parsed.RawQuery = q.Encode()
	database, err := db.Open(ctx, parsed.String())
	if err != nil {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close(context.Background())
		t.Fatal(err)
	}
	t.Cleanup(func() {
		database.Close()
		_, err := admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		if err != nil {
			t.Error("isolated load schema cleanup failed")
		}
		_ = admin.Close(context.Background())
	})
	return database
}
func loadPayload(t *testing.T, marker byte) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/stream" {
			_, _ = w.Write([]byte(strings.Repeat(string(marker), 65536)))
			return
		}
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		chunk := []byte(strings.Repeat(string(marker), 32768))
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
				if _, err := w.Write(chunk); err != nil {
					return
				}
				w.(http.Flusher).Flush()
			}
		}
	}))
	t.Cleanup(server.Close)
	return server
}
func loadEcho(t *testing.T, marker byte) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		packet := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(packet)
			if err != nil {
				return
			}
			reply := append([]byte{marker}, packet[:n]...)
			_, _ = conn.WriteTo(reply, addr)
		}
	}()
	return conn
}
func loadExit(t *testing.T, spec *config.Spec, strategy mimic.Strategy, tcp, udp string) *proxy.Runner {
	t.Helper()
	raw, err := config.BuildExitXRayJSON(spec, strategy, "error")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err = json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	freedom := func(tag, destination string) map[string]any {
		return map[string]any{"tag": tag, "protocol": "freedom", "settings": map[string]any{"redirect": destination, "finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.0/8"}}}}}
	}
	cfg["outbounds"] = []any{freedom("tcp", tcp), freedom("udp", udp)}
	cfg["routing"] = map[string]any{"rules": []any{map[string]any{"type": "field", "network": "udp", "outboundTag": "udp"}, map[string]any{"type": "field", "network": "tcp", "outboundTag": "tcp"}}}
	raw, _ = json.Marshal(cfg)
	r := new(proxy.Runner)
	if err = r.StartJSON(raw); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}
func encryptedLoadArtifact(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, 4*1024*1024)
	_, err = rand.Read(plain)
	if err != nil {
		t.Fatal(err)
	}
	return aead.Seal(nil, nonce, plain, nil)
}

// This combines real TCP/UDP clients, durable shipping to isolated PostgreSQL,
// immutable encrypted artifact copying and exit failure. It does not claim an
// actual pg_dump/key recovery or physical-device acceptance under that load.
func TestFiveClientsDuringDurableShippingArtifactCopyAndFailover(t *testing.T) {
	database := loadDatabase(t)
	payloadA := loadPayload(t, 'a')
	payloadB := loadPayload(t, 'b')
	udpA := loadEcho(t, 'a')
	udpB := loadEcho(t, 'b')
	cert, key, pin := cacheTestCertificate(t)
	strategy, err := mimic.New("apijson")
	if err != nil {
		t.Fatal(err)
	}
	spec := &config.Spec{Role: config.RoleBridge, DevMode: true, ListenAddress: "127.0.0.1", VLESSPort: cacheTestPort(t), AdminListen: fmt.Sprintf("127.0.0.1:%d", cacheTestPort(t)), SplitRouting: config.BoolPtr(false), SplithttpHost: "cache.test", SplitHTTPTLS: config.SplitHTTPTLSSpec{ServerName: "cache.test"}, TunnelTLSProvision: config.TunnelTLSSelfSigned, ProbeURLs: []string{payloadA.URL}, Database: &config.DatabaseSpec{DSN: "postgres://unused:unused@127.0.0.1:1/control_disabled"}}
	tunnel := uuid.NewString()
	nodes := []exits.Node{{ID: uuid.NewString(), Address: "127.0.0.1", Port: cacheTestPort(t), TunnelUUID: tunnel, PinnedPeerCertSHA256: pin, Priority: 100, Enabled: true}, {ID: uuid.NewString(), Address: "127.0.0.1", Port: cacheTestPort(t), TunnelUUID: tunnel, PinnedPeerCertSHA256: pin, Priority: 200, Enabled: true}}
	makeExit := func(n exits.Node, tcp, udp string) *proxy.Runner {
		copy := *spec
		copy.Role = config.RoleExit
		copy.VLESSPort = n.Port
		copy.Exit.TunnelUUID = tunnel
		copy.ExitCertPaths = config.CertPaths{CertFile: cert, KeyFile: key}
		return loadExit(t, &copy, strategy, tcp, udp)
	}
	primary := makeExit(nodes[0], payloadA.Listener.Addr().String(), udpA.LocalAddr().String())
	_ = makeExit(nodes[1], payloadB.Listener.Addr().String(), udpB.LocalAddr().String())
	users := make([]auth.User, 5)
	now := time.Now().UTC()
	pool := runtimestate.ProviderPoolID("vultr")
	limits := []runtimestate.QuotaLimit{{ExitID: pool, Scope: "provider_pool", Members: []string{nodes[0].ID, nodes[1].ID}, Period: now.Format("2006-01"), LimitBytes: 128 * 1024 * 1024, ExpiresAt: now.Add(runtimeLease)}}
	for _, node := range nodes {
		if _, err := database.Pool.Exec(context.Background(), `INSERT INTO quota_exit_membership(exit_id,scope) VALUES($1,'vultr')`, node.ID); err != nil {
			t.Fatal(err)
		}
	}
	for i := range users {
		users[i] = auth.User{UUID: uuid.NewString(), AccountID: uuid.NewString(), IsActive: true, Routes: []auth.RouteCredential{{UUID: uuid.NewString(), ExitID: &nodes[0].ID}}}
		limits = append(limits, runtimestate.QuotaLimit{AccountID: users[i].AccountID, ExitID: pool, Scope: "provider_pool", Period: now.Format("2006-01"), LimitBytes: 32 * 1024 * 1024, ExpiresAt: now.Add(runtimeLease)})
		for _, n := range nodes {
			limits = append(limits, runtimestate.QuotaLimit{PoolScope: "vultr", AccountID: users[i].AccountID, ExitID: n.ID, Period: now.Format("2006-01"), LimitBytes: 32 * 1024 * 1024, ExpiresAt: now.Add(runtimeLease)})
		}
	}
	for _, n := range nodes {
		limits = append(limits, runtimestate.QuotaLimit{PoolScope: "vultr", ExitID: n.ID, Period: now.Format("2006-01"), LimitBytes: 128 * 1024 * 1024, ExpiresAt: now.Add(runtimeLease)})
	}
	path := filepath.Join(t.TempDir(), "runtime.db")
	store, err := runtimestate.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := runtimeSnapshotV1{Version: 3, Fingerprint: runtimeFingerprint(spec), Users: snapshotUsers(users), Nodes: nodes, Limits: limits}
	raw, _ := json.Marshal(snapshot)
	if err = store.SaveSnapshot(runtimestate.Snapshot{Revision: 1, ConfirmedAt: now, Payload: raw}, limits); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	runner := &loadRuntimeRunner{cacheIntegrationRunner: &cacheIntegrationRunner{Runner: new(proxy.Runner), healthPort: cacheTestPort(t)}, state: make(chan *runtimestate.Store, 1)}
	ctx, cancelBridge := context.WithCancel(context.Background())
	bridgeDone := make(chan error, 1)
	go func() {
		bridgeDone <- runBridge(ctx, spec, "unused", path, "combined-token", runner, strategy, "error", slog.New(slog.NewTextHandler(io.Discard, nil)), bridgeOptions{CacheOnly: true, probeInterval: 100 * time.Millisecond})
	}()
	var stopOnce sync.Once
	stopBridge := func() {
		stopOnce.Do(func() {
			cancelBridge()
			select {
			case err := <-bridgeDone:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(5 * time.Second):
				t.Error("combined relay shutdown blocked")
			}
		})
	}
	t.Cleanup(stopBridge)
	waitCacheDiagnostics(t, spec, "combined-token")
	select {
	case store = <-runner.state:
	case <-time.After(time.Second):
		t.Fatal("real accounting store unavailable")
	}
	receiver := &loadTrafficReceiver{TrafficRepo: db.NewTrafficRepo(database)}
	collector := stats.NewDurable(runner, receiver, loadUsers(users), store, nil)
	work, cancelWork := context.WithCancel(context.Background())
	var background sync.WaitGroup
	flows, cancelFlows := context.WithCancel(context.Background())
	var traffic sync.WaitGroup
	stopFlows := func() { cancelFlows(); traffic.Wait(); cancelWork(); background.Wait() }
	var loadOnce sync.Once
	t.Cleanup(func() { loadOnce.Do(stopFlows) })
	problems := make(chan error, 16)
	background.Add(1)
	go func() {
		defer background.Done()
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-work.Done():
				return
			case <-ticker.C:
				c, cancel := context.WithTimeout(work, 2*time.Second)
				err := collector.Checkpoint(c)
				if err == nil {
					err = collector.Replay(c)
				}
				cancel()
				if err != nil && !errors.Is(err, errLoadLostAck) && work.Err() == nil {
					problems <- err
					return
				}
			}
		}
	}()
	artifact := encryptedLoadArtifact(t)
	expectedHash := sha256.Sum256(artifact)
	directory := t.TempDir()
	var copies atomic.Int64
	background.Add(1)
	go func() {
		defer background.Done()
		for work.Err() == nil {
			temporary := filepath.Join(directory, "artifact.pending")
			if err := os.WriteFile(temporary, artifact, 0600); err != nil {
				problems <- err
				return
			}
			if err := os.Rename(temporary, filepath.Join(directory, "artifact.ready")); err != nil {
				problems <- err
				return
			}
			data, err := os.ReadFile(filepath.Join(directory, "artifact.ready"))
			if err != nil || sha256.Sum256(data) != expectedHash {
				problems <- errors.New("immutable copied artifact corrupted")
				return
			}
			copies.Add(1)
			select {
			case <-work.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()
	var tcpA, tcpB, echoA, echoB [5]atomic.Int64
	for i, user := range users {
		client := new(proxy.Runner)
		raw, _ := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "error"}, "outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": spec.VLESSPort, "users": []any{map[string]any{"id": user.Routes[0].UUID, "encryption": "none"}}}}}, "streamSettings": map[string]any{"network": "tcp", "security": "none"}}}})
		if err = client.StartJSON(raw); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			loadOnce.Do(stopFlows)
			_ = client.Close()
		})
		index := i
		traffic.Add(2)
		go func() {
			defer traffic.Done()
			tr := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				dest, err := xnet.ParseDestination(network + ":" + address)
				if err != nil {
					return nil, err
				}
				return core.Dial(ctx, client.Instance(), dest)
			}}
			defer tr.CloseIdleConnections()
			hc := &http.Client{Transport: tr}
			for flows.Err() == nil {
				req, _ := http.NewRequestWithContext(flows, "GET", payloadA.URL+"/stream", nil)
				resp, err := hc.Do(req)
				if err != nil {
					select {
					case <-flows.Done():
						return
					case <-time.After(50 * time.Millisecond):
					}
					continue
				}
				buf := make([]byte, 32768)
				for {
					n, err := resp.Body.Read(buf)
					if n > 0 {
						switch buf[0] {
						case 'a':
							tcpA[index].Add(int64(n))
						case 'b':
							tcpB[index].Add(int64(n))
						}
					}
					if err != nil {
						break
					}
				}
				_ = resp.Body.Close()
			}
		}()
		go func() {
			defer traffic.Done()
			dest, err := xnet.ParseDestination("udp:" + udpA.LocalAddr().String())
			if err != nil {
				problems <- err
				return
			}
			for flows.Err() == nil {
				conn, err := core.Dial(flows, client.Instance(), dest)
				if err != nil {
					select {
					case <-flows.Done():
						return
					case <-time.After(50 * time.Millisecond):
					}
					continue
				}
				for flows.Err() == nil {
					_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
					if _, err = conn.Write([]byte("combined-echo")); err != nil {
						break
					}
					reply := make([]byte, 64)
					n, err := conn.Read(reply)
					if err != nil {
						break
					}
					if n == 14 && string(reply[1:n]) == "combined-echo" {
						switch reply[0] {
						case 'a':
							echoA[index].Add(1)
						case 'b':
							echoB[index].Add(1)
						}
					}
					select {
					case <-flows.Done():
					case <-time.After(100 * time.Millisecond):
					}
				}
				_ = conn.Close()
			}
		}()
	}
	// Stop traffic before client cores on normal and assertion-failure cleanup;
	// the earlier registration also covers a partially constructed fixture.
	t.Cleanup(func() { loadOnce.Do(stopFlows) })
	allReady := func(a, b *[5]atomic.Int64) bool {
		for i := range a {
			if a[i].Load() == 0 || b[i].Load() == 0 {
				return false
			}
		}
		return true
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !allReady(&tcpA, &echoA) {
		time.Sleep(50 * time.Millisecond)
	}
	if !allReady(&tcpA, &echoA) {
		t.Fatal("not all five clients established TCP and UDP on primary")
	}
	// Include at least one normal five-second periodic checkpoint while streams,
	// PostgreSQL replay and artifact copies are all active.
	time.Sleep(5 * time.Second)
	if receiver.calls.Load() < 2 || copies.Load() < 2 {
		t.Fatal("background shipping or immutable copy did not overlap streams")
	}
	if err = primary.Close(); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) && !allReady(&tcpB, &echoB) {
		time.Sleep(50 * time.Millisecond)
	}
	if !allReady(&tcpB, &echoB) {
		t.Fatal("not all five clients recovered TCP and UDP on backup")
	}
	loadOnce.Do(stopFlows)
	if err = collector.Checkpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = collector.Replay(context.Background()); err != nil {
		t.Fatal(err)
	}
	stopBridge()
	// Replay the shutdown checkpoint from a reopened journal, as a later process
	// would do. The relay exclusively owns bbolt while running.
	store, err = runtimestate.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	finalCollector := stats.NewDurable(runner, receiver, loadUsers(users), store, nil)
	if err = finalCollector.Replay(context.Background()); err != nil {
		t.Fatal(err)
	}
	if pending, _, _, err := store.PendingStats(); err != nil || pending != 0 {
		t.Fatalf("shutdown journal not acknowledged: pending=%d err=%v", pending, err)
	}
	var expectedCharge, sharedCharge int64
	for _, user := range users {
		personal, global, err := store.PoolUsage(user.AccountID, "vultr")
		if err != nil {
			t.Fatal(err)
		}
		expectedCharge += personal
		sharedCharge = global
	}
	if sharedCharge != expectedCharge {
		t.Fatal("shared pool and personal totals diverged", sharedCharge, expectedCharge)
	}
	close(problems)
	for err := range problems {
		t.Error("combined background worker", err)
	}
	var accounts int
	var actual, charged int64
	if err = database.Pool.QueryRow(context.Background(), `SELECT count(DISTINCT account_id),COALESCE(sum(uplink_bytes+downlink_bytes),0)::bigint,COALESCE(sum(charged_bytes),0)::bigint FROM account_exit_usage`).Scan(&accounts, &actual, &charged); err != nil {
		t.Fatal(err)
	}
	if accounts != 5 || actual <= 5*65536 || charged < actual || charged != expectedCharge {
		t.Fatalf("durable load accounting invalid: accounts=%d actual=%d charged=%d expected=%d", accounts, actual, charged, expectedCharge)
	}
	t.Logf("five TCP+UDP clients, checkpoints/replay including lost commit reply, artifact copies=%d, confirmed bytes=%d", copies.Load(), actual)
}

type loadUsers []auth.User

func (u loadUsers) List() []auth.User { return u }
