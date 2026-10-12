package config

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/NikitaDmitryuk/ultra/internal/proxy"
	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
	"github.com/google/uuid"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise the actual loopback primary backend and its durable meter behind
// TLS/H2 -> H2C streaming. Nginx itself is intentionally outside this core test.
func TestPrimaryXHTTPServerFirstInteractiveSmallPayload(t *testing.T) {
	primaryInteractiveFixture(t, false)
}
func TestActualNginxPrimaryXHTTPServerFirstInteractiveSmallPayload(t *testing.T) {
	if os.Getenv("ULTRA_TEST_NGINX_IMAGE") == "" {
		t.Skip("explicit isolated Nginx image not provided")
	}
	primaryInteractiveFixture(t, true)
}
func primaryInteractiveFixture(t *testing.T, nginx bool) {
	spec := bridgeSpecForAntiCensorTest()
	spec.DevMode = false
	spec.SplitRouting = BoolPtr(false)
	spec.LegacyPublicEnabled = BoolPtr(false)
	spec.GatewayVLESSPort = 0
	spec.PrimaryXHTTP = &PrimaryXHTTPIngress{Host: "127.0.0.1", BackendPort: freePort(t), PublicXHTTPTLSSpec: PublicXHTTPTLSSpec{Port: freePort(t), ServerName: "example.com", Path: "/interactive", Mode: "stream-up"}}
	user := auth.User{UUID: uuid.NewString(), AccountID: uuid.NewString(), Kind: "vless", IsActive: true}
	strategy, _ := mimic.New("steamlike")
	raw, err := BuildBridgeXRayJSON(spec, []auth.User{user}, nil, "", strategy, "error")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err = json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	inbounds := []any{}
	for _, v := range cfg["inbounds"].([]any) {
		if strings.HasSuffix(v.(map[string]any)["tag"].(string), "-primary-xhttp") {
			inbounds = append(inbounds, v)
		}
	}
	cfg["inbounds"] = inbounds
	cfg["outbounds"] = []any{map[string]any{"protocol": "freedom", "tag": "to-exit-fixture", "settings": map[string]any{"domainStrategy": "UseIP", "finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.0/8"}}}}}}
	delete(cfg, "routing")
	delete(cfg, "dns")
	raw, _ = json.Marshal(cfg)
	state, err := runtimestate.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = state.Close() }()
	now := time.Now().UTC()
	limits := []runtimestate.QuotaLimit{{AccountID: user.AccountID, ExitID: "fixture", Period: now.Format("2006-01"), LimitBytes: 1 << 20, ExpiresAt: now.Add(time.Hour)}, {ExitID: "fixture", Period: now.Format("2006-01"), LimitBytes: 1 << 20, ExpiresAt: now.Add(time.Hour)}}
	if err = state.SaveSnapshot(runtimestate.Snapshot{ConfirmedAt: now, Payload: []byte(`{}`)}, limits); err != nil {
		t.Fatal(err)
	}
	relay := &proxy.Runner{}
	if err = relay.ConfigureAccounting(state, []auth.User{user}); err != nil {
		t.Fatal(err)
	}
	if err = relay.StartJSON(raw); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = relay.Close() }()
	cert, key := testCertificate(t)
	if nginx {
		spec.PrimaryXHTTP.Port = nginxInteractiveFrontend(t, spec.PrimaryXHTTP, cert, key)
	} else {
		backend, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", spec.PrimaryXHTTP.BackendPort))
		reverse := httputil.NewSingleHostReverseProxy(backend)
		reverse.FlushInterval = -1
		protocols := new(http.Protocols)
		protocols.SetUnencryptedHTTP2(true)
		transport := &http.Transport{Protocols: protocols}
		defer transport.CloseIdleConnections()
		reverse.Transport = transport
		front := httptest.NewUnstartedServer(reverse)
		front.EnableHTTP2 = true
		pair, e := tls.LoadX509KeyPair(cert, key)
		if e != nil {
			t.Fatal(e)
		}
		front.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
		front.StartTLS()
		defer front.Close()
		spec.PrimaryXHTTP.Port = front.Listener.Addr().(*net.TCPAddr).Port
	}
	export, err := BuildSubscriptionExport(spec, user, "")
	if err != nil {
		t.Fatal(err)
	}
	export.XRayOutboundJSON["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)["certificates"] = []any{map[string]any{"certificateFile": cert, "usage": "verify"}}
	raw, _ = json.Marshal(map[string]any{"log": map[string]any{"loglevel": "error"}, "outbounds": []any{export.XRayOutboundJSON}})
	client := &proxy.Runner{}
	if err = client.StartJSON(raw); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	const banner = "SSH-2.0-ultra-interactive-fixture\r\n"
	for attempt := range 5 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		finished := make(chan error, 1)
		go func() {
			conn, e := listener.Accept()
			if e != nil {
				finished <- e
				return
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, e = io.WriteString(conn, banner); e != nil {
				finished <- e
				return
			}
			for round := range 3 {
				want := strings.Repeat(string(rune('a'+round)), 20+round*30)
				buf := make([]byte, len(want))
				if _, e = io.ReadFull(conn, buf); e != nil {
					finished <- e
					return
				}
				if string(buf) != want {
					finished <- fmt.Errorf("interactive payload mismatch")
					return
				}
				if _, e = conn.Write(buf); e != nil {
					finished <- e
					return
				}
			}
			finished <- nil
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		dest, _ := xnet.ParseDestination("tcp:" + listener.Addr().String())
		conn, e := core.Dial(ctx, client.Instance(), dest)
		if e == nil {
			_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
			got := make([]byte, len(banner))
			_, e = io.ReadFull(conn, got)
			if e == nil && string(got) != banner {
				e = fmt.Errorf("server-first banner mismatch")
			}
			for round := 0; e == nil && round < 3; round++ {
				want := strings.Repeat(string(rune('a'+round)), 20+round*30)
				_, e = io.WriteString(conn, want)
				if e == nil {
					got = make([]byte, len(want))
					_, e = io.ReadFull(conn, got)
					if e == nil && string(got) != want {
						e = fmt.Errorf("small response mismatch")
					}
				}
			}
			_ = conn.Close()
		}
		cancel()
		_ = listener.Close()
		if e != nil {
			t.Fatalf("primary interactive attempt%d: %v", attempt, e)
		}
		if e = <-finished; e != nil {
			t.Fatal(e)
		}
	}
	traffic := relay.DrainAccountTraffic()[user.AccountID]["to-exit-fixture"]
	if traffic[0] != 750 || traffic[1] != int64(750+5*len(banner)) {
		t.Fatalf("small streams were not accounted: %v", traffic)
	}
}

func nginxInteractiveFrontend(t *testing.T, primary *PrimaryXHTTPIngress, cert, key string) int {
	t.Helper()
	image := os.Getenv("ULTRA_TEST_NGINX_IMAGE")
	if !strings.HasPrefix(image, "nginx:") {
		t.Fatal("official Nginx image required")
	}
	fixture := t.TempDir()
	for _, file := range []struct{ source, target string }{{cert, "cert.pem"}, {key, "key.pem"}} {
		data, e := os.ReadFile(file.source)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(fixture, file.target), data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	source, e := filepath.Abs("../install/scripts/xhttp-ingress.py")
	if e != nil {
		t.Fatal(e)
	}
	script := `import importlib.util,sys
spec=importlib.util.spec_from_file_location('ingress',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
sys.stdout.buffer.write(m.nginx({'domain':'example.com','path':'/interactive','backend_port':int(sys.argv[2])},int(sys.argv[3])))`
	data, e := exec.Command("python3", "-c", script, source, fmt.Sprint(primary.BackendPort), fmt.Sprint(primary.Port)).Output()
	if e != nil {
		t.Fatal(e)
	}
	conf := string(data)
	conf = strings.ReplaceAll(conf, "listen 80;", fmt.Sprintf("listen 127.0.0.1:%d;", freePort(t)))
	conf = strings.ReplaceAll(conf, fmt.Sprintf("listen %d ssl http2;", primary.Port), fmt.Sprintf("listen 127.0.0.1:%d ssl http2;", primary.Port))
	conf = strings.ReplaceAll(conf, "/etc/letsencrypt/live/example.com/fullchain.pem", "/fixtures/cert.pem")
	conf = strings.ReplaceAll(conf, "/etc/letsencrypt/live/example.com/privkey.pem", "/fixtures/key.pem")
	conf = strings.ReplaceAll(conf, "/var/log/nginx/ultra-vpn-error.log crit", "stderr warn")
	conf = "worker_processes 1; error_log stderr warn; pid /tmp/nginx.pid; events {} http { client_body_temp_path /tmp/body; proxy_temp_path /tmp/proxy; fastcgi_temp_path /tmp/fastcgi; uwsgi_temp_path /tmp/uwsgi; scgi_temp_path /tmp/scgi;\n" + conf + "\n}\n"
	if e = os.WriteFile(filepath.Join(fixture, "nginx.conf"), []byte(conf), 0600); e != nil {
		t.Fatal(e)
	}
	name := "ultra-nginx-interactive-" + uuid.NewString()
	output, e := exec.Command("docker", "run", "--detach", "--rm", "--name", name, "--network", "host", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "--mount", "type=bind,src="+fixture+",dst=/fixtures,readonly", "--entrypoint", "nginx", image, "-c", "/fixtures/nginx.conf", "-g", "daemon off;").CombinedOutput()
	if e != nil {
		t.Fatalf("isolated Nginx start: %v %s", e, output)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
			t.Logf("isolated Nginx logs: %s", logs)
		}
		_ = exec.Command("docker", "rm", "--force", name).Run()
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", primary.Port), 50*time.Millisecond)
		if e == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("isolated Nginx did not listen")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return primary.Port
}
