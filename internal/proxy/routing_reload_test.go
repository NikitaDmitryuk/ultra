package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
	xraylog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	xlog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"google.golang.org/protobuf/proto"
)

type routingLogHandler func(xlog.Message)

func (handler routingLogHandler) Handle(message xlog.Message) { handler(message) }

func TestHealthRoutingPreservesGlobalLogger(t *testing.T) {
	configuration := func(tag string) []byte {
		return []byte(
			fmt.Sprintf(
				`{"log":{"loglevel":"error"},"outbounds":[{"tag":"a","protocol":"freedom"},{"tag":"b","protocol":"freedom"}],"routing":{"rules":[{"type":"field","network":"tcp,udp","outboundTag":%q}]}}`,
				tag,
			),
		)
	}
	var runner Runner
	if err := runner.StartJSON(configuration("a")); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = runner.Close() }()
	activeLogger := runner.Instance().GetFeature(new(xraylog.Instance)).(*xraylog.Instance)
	defer xlog.RegisterHandler(activeLogger)
	var records atomic.Int64
	xlog.RegisterHandler(routingLogHandler(func(message xlog.Message) {
		if message.String() == "health-routing-log-probe" {
			records.Add(1)
		}
	}))
	for i, tag := range []string{"b", "a"} {
		if err := runner.ReloadReason(configuration(tag), "exit health selection"); err != nil {
			t.Fatal(err)
		}
		xlog.Record(routingLogMessage("health-routing-log-probe"))
		if records.Load() != int64(i+1) {
			t.Fatal("health routing replaced the process-global log handler")
		}
	}
}

type routingLogMessage string

func (message routingLogMessage) String() string { return string(message) }

func TestHealthRoutingCandidateBoundaries(t *testing.T) {
	base := `{"log":{"loglevel":"error"},"outbounds":[{"tag":"a","protocol":"freedom"}],"routing":{"domainStrategy":"AsIs","rules":[{"type":"field","network":"tcp","outboundTag":"a"}]}}`
	previous, err := loadCoreConfig([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	original := proto.Clone(previous)
	for _, tc := range []struct {
		name, change string
		want         bool
	}{
		{"rules", `{"rules":[{"type":"field","network":"udp","outboundTag":"a"}]}`, true},
		{"domain strategy", `{"domainStrategy":"IPIfNonMatch","rules":[{"type":"field","network":"tcp","outboundTag":"a"}]}`, false},
		{"balancers", `{"balancers":[{"tag":"b","selector":["a"],"strategy":{"type":"random"}}],"rules":[{"type":"field","network":"tcp","outboundTag":"a"}]}`, false},
		{"nonrouting", `{"rules":[{"type":"field","network":"udp","outboundTag":"a"}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg map[string]any
			if e := json.Unmarshal([]byte(base), &cfg); e != nil {
				t.Fatal(e)
			}
			var routing any
			if e := json.Unmarshal([]byte(tc.change), &routing); e != nil {
				t.Fatal(e)
			}
			cfg["routing"] = routing
			if tc.name == "nonrouting" {
				cfg["log"] = map[string]any{"loglevel": "warning"}
			}
			data, _ := json.Marshal(cfg)
			next, e := loadCoreConfig(data)
			if e != nil {
				t.Fatal(e)
			}
			unchanged := proto.Clone(next)
			if got := healthRoutingCandidate(previous, next) != nil; got != tc.want {
				t.Fatalf("eligible=%t, want %t", got, tc.want)
			}
			if !proto.Equal(next, unchanged) || !proto.Equal(previous, original) {
				t.Fatal("candidate comparison mutated configuration")
			}
		})
	}
}

func TestHealthRoutingPreservesEstablishedAccountedTransfer(t *testing.T) {
	startTarget := func(label byte) net.Listener {
		listener, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = listener.Close() })
		go func() {
			for {
				conn, e := listener.Accept()
				if e != nil {
					return
				}
				go func() {
					defer func() { _ = conn.Close() }()
					packet := make([]byte, 1)
					for {
						if _, e := io.ReadFull(conn, packet); e != nil {
							return
						}
						if _, e := conn.Write([]byte{label, packet[0]}); e != nil {
							return
						}
					}
				}()
			}
		}()
		return listener
	}
	a, b := startTarget('a'), startTarget('b')
	config := func(target string, invalid bool) []byte {
		rules := []any{map[string]any{"type": "field", "network": "tcp", "outboundTag": target}}
		if invalid {
			rules = []any{
				map[string]any{"type": "field", "network": "tcp", "outboundTag": target, "ruleTag": "duplicate"},
				map[string]any{"type": "field", "network": "udp", "outboundTag": target, "ruleTag": "duplicate"},
			}
		}
		data, e := json.Marshal(map[string]any{
			"log": map[string]any{"loglevel": "error"},
			"outbounds": []any{
				map[string]any{"protocol": "freedom", "tag": "to-exit-a", "settings": map[string]any{"redirect": a.Addr().String()}},
				map[string]any{"protocol": "freedom", "tag": "to-exit-b", "settings": map[string]any{"redirect": b.Addr().String()}},
			},
			"routing": map[string]any{"domainStrategy": "AsIs", "rules": rules},
		})
		if e != nil {
			t.Fatal(e)
		}
		return data
	}
	store, err := runtimestate.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	now := time.Now().UTC()
	var limits []runtimestate.QuotaLimit
	for _, exit := range []string{"a", "b"} {
		for _, account := range []string{"", "owner"} {
			limits = append(
				limits,
				runtimestate.QuotaLimit{
					AccountID:  account,
					ExitID:     exit,
					Period:     now.Format("2006-01"),
					LimitBytes: 1024 * 1024,
					ExpiresAt:  now.Add(time.Hour),
				},
			)
		}
	}
	if err = store.SaveSnapshot(runtimestate.Snapshot{ConfirmedAt: now, Payload: []byte(`{}`)}, limits); err != nil {
		t.Fatal(err)
	}
	var r Runner
	user := auth.User{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee", AccountID: "owner"}
	if err = r.ConfigureAccounting(store, []auth.User{user}); err != nil {
		t.Fatal(err)
	}
	if err = r.StartJSON(config("to-exit-a", false)); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	instance := r.Instance()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = session.ContextWithInbound(ctx, &session.Inbound{User: &protocol.MemoryUser{Email: user.UUID}})
	dial := func() net.Conn {
		conn, e := core.Dial(ctx, r.Instance(), xnet.TCPDestination(xnet.LocalHostIP, 80))
		if e != nil {
			t.Fatal(e)
		}
		return conn
	}
	exchange := func(conn net.Conn) (byte, error) {
		if _, e := conn.Write([]byte("x")); e != nil {
			return 0, e
		}
		packet := make([]byte, 2)
		_, e := io.ReadFull(conn, packet)
		return packet[0], e
	}
	established := dial()
	defer func() { _ = established.Close() }()
	if label, e := exchange(established); e != nil || label != 'a' {
		t.Fatalf("initial target=%c, err=%v", label, e)
	}
	for i, target := range []string{"b", "a"} {
		if err = r.ReloadReason(config("to-exit-"+target, false), "exit health selection"); err != nil {
			t.Fatal(err)
		}
		if r.Instance() != instance || r.Status().Count != 1 || r.Status().RoutingCount != uint64(i+1) {
			t.Fatal("health routing replaced core", r.Status())
		}
		if label, e := exchange(established); e != nil || label != 'a' {
			t.Fatalf("established target=%c, err=%v", label, e)
		}
		fresh := dial()
		label, e := exchange(fresh)
		_ = fresh.Close()
		if e != nil || label != target[0] {
			t.Fatalf("new target=%c want=%s, err=%v", label, target, e)
		}
	}
	if err = r.ReloadReason(config("to-exit-b", true), "exit health selection"); err == nil {
		t.Fatal("invalid rule candidate accepted")
	}
	if r.Instance() != instance || r.Status().RoutingCount != 2 {
		t.Fatal("invalid candidate changed running core")
	}
	fresh := dial()
	label, e := exchange(fresh)
	_ = fresh.Close()
	if e != nil || label != 'a' {
		t.Fatalf("invalid candidate replaced original routes: %c %v", label, e)
	}
	measured := r.DrainAccountTraffic()
	for _, exit := range []string{"a", "b"} {
		if measured["owner"]["to-exit-"+exit][0] <= 0 || measured["owner"]["to-exit-"+exit][1] <= 0 {
			t.Fatalf("accounting lost for %s: %v", exit, measured)
		}
	}
	if err = r.ReloadReason(config("to-exit-b", false), "confirmed database state"); err != nil {
		t.Fatal(err)
	}
	if _, e = exchange(established); e == nil {
		t.Fatal("administrative reload retained old transfer")
	}
	if r.Instance() == instance || r.Status().Count != 2 || r.Status().RoutingCount != 2 {
		t.Fatal("administrative reload skipped lifecycle", r.Status())
	}
}

func TestHealthRoutingGRPCRequiresFullReload(t *testing.T) {
	for _, network := range []string{"grpc", "gun"} {
		t.Run(network, func(t *testing.T) {
			config := func(target string) []byte {
				return []byte(
					fmt.Sprintf(
						`{"outbounds":[{"tag":"a","protocol":"freedom","streamSettings":{"network":"grpc","grpcSettings":{"serviceName":"fixture"}}}],"routing":{"rules":[{"type":"field","network":%q,"outboundTag":"a"}]}}`,
						target,
					),
				)
			}
			cfg, err := loadCoreConfig(config("tcp"))
			if err != nil {
				t.Fatal(err)
			}
			if network == "gun" {
				// This parser currently rejects gun in JSON. Still gate the typed
				// alias conservatively if a future parser emits it.
				value, e := cfg.Outbound[0].SenderSettings.GetInstance()
				if e != nil {
					t.Fatal(e)
				}
				sender := value.(*proxyman.SenderConfig)
				sender.StreamSettings.ProtocolName = "gun"
				cfg.Outbound[0].SenderSettings = serial.ToTypedMessage(sender)
			}
			if !hasGRPCOutbound(cfg) {
				t.Fatal("gRPC alias escaped conservative gate")
			}
			if network == "gun" {
				return
			}
			var r Runner
			if err = r.StartJSON(config("tcp")); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = r.Close() }()
			instance := r.Instance()
			if err = r.ReloadReason(config("udp"), "exit health selection"); err != nil {
				t.Fatal(err)
			}
			if r.Instance() == instance || r.Status().Count != 2 || r.Status().RoutingCount != 0 {
				t.Fatal("gRPC health update preserved stale outbound")
			}
		})
	}
}

func TestHealthRoutingNonRuleChangeReplacesCore(t *testing.T) {
	for _, change := range []string{
		`"domainStrategy":"IPIfNonMatch",`,
		`"balancers":[{"tag":"balanced","selector":["a"],"strategy":{"type":"random"}}],`,
	} {
		t.Run(change, func(t *testing.T) {
			var r Runner
			base := `{"outbounds":[{"tag":"a","protocol":"freedom"}],"routing":{%s"rules":[{"type":"field","network":"tcp","outboundTag":"a"}]}}`
			if err := r.StartJSON([]byte(fmt.Sprintf(base, ""))); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = r.Close() }()
			instance := r.Instance()
			if err := r.ReloadReason([]byte(fmt.Sprintf(base, change)), "exit health selection"); err != nil {
				t.Fatal(err)
			}
			if r.Instance() == instance || r.Status().Count != 2 || r.Status().RoutingCount != 0 {
				t.Fatal("unsafe routing change applied without lifecycle")
			}
		})
	}
}
