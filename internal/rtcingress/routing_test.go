package rtcingress

import (
	"context"
	"encoding/json"
	_ "github.com/xtls/xray-core/main/distro/all"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/NikitaDmitryuk/ultra/internal/proxy"
	"github.com/NikitaDmitryuk/ultra/internal/rtc"
	socks "golang.org/x/net/proxy"
)

func rtcTestBinding(t *testing.T, id, user string) rtc.Binding {
	t.Helper()
	root := t.TempDir()
	b := rtc.Binding{ID: id, UserUUID: user, Enabled: true, Provider: "wbstream", RoomID: id, Transport: "vp8channel", ListenPort: freePort(t), KeyFile: filepath.Join(root, "key"), PasswordFile: filepath.Join(root, "pass"), BootstrapDNS: "77.88.8.8:53"}
	for _, p := range []string{b.KeyFile, b.PasswordFile} {
		if e := os.WriteFile(p, []byte(strings.Repeat("a", 64)), 0600); e != nil {
			t.Fatal(e)
		}
	}
	return b
}

func TestRTCTransferRoutesAccountingAndRevocation(t *testing.T) {
	a := auth.User{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee", IsActive: true, EffectiveExitID: "a"}
	b := auth.User{UUID: "fa378e1b-cda7-409f-ac04-ef52f67770b0", IsActive: true, EffectiveExitID: "b"}
	ba, bb := rtcTestBinding(t, "phone-a", a.UUID), rtcTestBinding(t, "phone-b", b.UUID)
	spec := &config.Spec{Role: config.RoleBridge, Database: &config.DatabaseSpec{}, Stats: &config.StatsSpec{APIListen: net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t)))}, DevMode: true, ListenAddress: "127.0.0.1", VLESSPort: freePort(t), SplitRouting: config.BoolPtr(true), RoutingMode: config.RoutingModeBlocklist, GeositeExitTags: []string{""}, DomainDirect: []string{"full:direct.test"}, DomainExit: []string{"full:exit.test"}, RTCService: rtc.ServiceConfig{Enabled: true, ContentFile: "/private/content", Socket: "/private/control", GatewayPort: ba.ListenPort}}
	strategy, e := mimic.New("apijson")
	if e != nil {
		t.Fatal(e)
	}
	targets := map[string]string{}
	for _, tag := range []string{"direct", exits.OutboundTag("a"), exits.OutboundTag("b")} {
		dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(tag)) }))
		defer dest.Close()
		targets[tag] = strings.TrimPrefix(dest.URL, "http://")
	}
	build := func(users []auth.User) []byte {
		t.Helper()
		data, err := config.BuildBridgeXRayJSON(spec, users, []exits.Node{{ID: "a", Address: "127.0.0.1", Port: 1, TunnelUUID: a.UUID, Enabled: true}, {ID: "b", Address: "127.0.0.1", Port: 2, TunnelUUID: b.UUID, Enabled: true}}, "a", strategy, "none")
		if err != nil {
			t.Fatal(err)
		}
		var cfg map[string]any
		if err = json.Unmarshal(data, &cfg); err != nil {
			t.Fatal(err)
		}
		// Redirect only test outbounds to local HTTP servers; production routing is unchanged.
		outs := cfg["outbounds"].([]any)
		for i, v := range outs {
			tag := v.(map[string]any)["tag"].(string)
			if dest, ok := targets[tag]; ok {
				outs[i] = map[string]any{"tag": tag, "protocol": "freedom", "settings": map[string]any{"redirect": dest}}
			}
		}
		cfg["dns"] = map[string]any{"hosts": map[string]any{"direct.test": "192.0.2.1", "exit.test": "192.0.2.2", "private.test": "127.0.0.1"}, "servers": []string{}}
		data, err = json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	var runner proxy.Runner
	if e = runner.StartJSON(build([]auth.User{a, b})); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = runner.Close() }()
	gateway := NewGateway(runner.DialRTC, func(context.Context, string) bool { return true })
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(ba.ListenPort)))
	if err != nil {
		t.Fatal(err)
	}
	go gateway.Serve(listener)
	defer gateway.Close()
	bb.ListenPort = ba.ListenPort
	gateway.Grant(a.UUID, ba.ID, strings.Repeat("a", 64), false)
	gateway.Grant(b.UUID, bb.ID, strings.Repeat("a", 64), false)

	get := func(binding rtc.Binding, host, password string) (string, error) {
		d, err := socks.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(binding.ListenPort)), &socks.Auth{User: binding.ID, Password: password}, &net.Dialer{Timeout: time.Second})
		if err != nil {
			return "", err
		}
		tr := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, n, addr string) (net.Conn, error) {
			return d.(socks.ContextDialer).DialContext(ctx, n, addr)
		}}
		defer tr.CloseIdleConnections()
		r, err := (&http.Client{Transport: tr, Timeout: 2 * time.Second}).Get("http://" + host + "/")
		if err != nil {
			return "", err
		}
		defer func() { _ = r.Body.Close() }()
		data, err := io.ReadAll(r.Body)
		return string(data), err
	}
	password := strings.Repeat("a", 64)
	for _, tc := range []struct {
		binding    rtc.Binding
		host, want string
	}{{ba, "exit.test", exits.OutboundTag("a")}, {bb, "exit.test", exits.OutboundTag("b")}, {ba, "direct.test", "direct"}} {
		got, err := get(tc.binding, tc.host, password)
		if err != nil || got != tc.want {
			t.Fatalf("route got %q, want %q: %v", got, tc.want, err)
		}
	}
	measured := runner.DrainRouteTraffic()
	if measured[a.UUID][exits.OutboundTag("a")][0] == 0 || measured[b.UUID][exits.OutboundTag("b")][1] == 0 || measured[a.UUID]["direct"][0] == 0 {
		t.Fatal("missing owner/outbound accounting", measured)
	}
	for _, host := range []string{"127.0.0.1", "private.test", "169.254.169.254"} {
		if _, err := get(ba, host, password); err == nil {
			t.Fatal("private destination allowed", host)
		}
	}
	if _, err := get(ba, "exit.test", "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
	a.EffectiveExitID = auth.BlockedExit
	if e = runner.Reload(build([]auth.User{a, b})); e != nil {
		t.Fatal(e)
	}
	if _, err := get(ba, "exit.test", password); err == nil {
		t.Fatal("quota escaped to direct")
	}
	if got, err := get(ba, "direct.test", password); err != nil || got != "direct" {
		t.Fatal("split direct lost")
	}
	gateway.Revoke(a.UUID)
	a.IsActive = false
	if e = runner.Reload(build([]auth.User{a, b})); e != nil {
		t.Fatal(e)
	}
	if _, err := get(ba, "exit.test", password); err == nil {
		t.Fatal("disabled user accepted")
	}
	if got, err := get(bb, "exit.test", password); err != nil || got != exits.OutboundTag("b") {
		t.Fatal("other owner affected", err)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}
