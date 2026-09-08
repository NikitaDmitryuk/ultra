package proxy

import (
	"bytes"
	"fmt"
	"net"
	"testing"

	_ "github.com/xtls/xray-core/main/distro/all"
)

func TestRunnerMinimalVLESS(t *testing.T) {
	const cfg = `{
  "log": {"loglevel": "error"},
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": 0,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "2784871e-d8a9-4e1f-b831-3d86aa8653ee"}],
      "decryption": "none"
    },
    "streamSettings": {"network": "tcp", "security": "none"}
  }],
  "outbounds": [{
    "protocol": "freedom",
    "tag": "direct"
  }],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [{"type": "field", "network": "tcp,udp", "outboundTag": "direct"}]
  }
}`

	var r Runner
	if err := r.StartJSON([]byte(cfg)); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if err := r.Reload([]byte(cfg)); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerEmptyVLESSClients(t *testing.T) {
	const cfg = `{
  "log": {"loglevel": "error"},
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": 0,
    "protocol": "vless",
    "settings": {
      "clients": [],
      "decryption": "none"
    },
    "streamSettings": {"network": "tcp", "security": "none"}
  }],
  "outbounds": [{
    "protocol": "freedom",
    "tag": "direct"
  }],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [{"type": "field", "network": "tcp,udp", "outboundTag": "direct"}]
  }
}`

	var r Runner
	if err := r.StartJSON([]byte(cfg)); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
}

func TestRunnerKeepsValidConfigAndSkipsEquivalent(t *testing.T) {
	var r Runner
	data := []byte(`{"outbounds":[{"protocol":"freedom"}]}`)
	if err := r.StartJSON(data); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	original := r.Instance()
	if err := r.Reload([]byte(`{ "outbounds": [ { "protocol": "freedom" } ] }`)); err != nil {
		t.Fatal(err)
	}
	if r.Instance() != original || r.Status().Count != 1 {
		t.Fatal("equivalent config restarted")
	}
	if err := r.Reload([]byte(`{"inbounds":[{"protocol":"invalid"}]}`)); err == nil {
		t.Fatal("accepted invalid config")
	}
	if r.Instance() != original {
		t.Fatal("invalid config stopped working core")
	}
}

func TestRunnerRestoresAfterListenerFailure(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = occupied.Close() }()
	var r Runner
	original := []byte(`{"outbounds":[{"protocol":"freedom"}]}`)
	if err := r.StartJSON(original); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	invalid := []byte(fmt.Sprintf(`{"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"socks","settings":{}}],"outbounds":[{"protocol":"freedom"}]}`, occupied.Addr().(*net.TCPAddr).Port))
	if err := r.Reload(invalid); err == nil {
		t.Fatal("occupied port accepted")
	}
	if r.Instance() == nil || r.Status().Error != "start failed" {
		t.Fatal("previous core not restored", r.Status())
	}
	if err := r.Reload(original); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerEquivalentXHTTPHeaders(t *testing.T) {
	data := []byte(`{"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":1,"users":[{"id":"2784871e-d8a9-4e1f-b831-3d86aa8653ee","encryption":"none"}]}]},"streamSettings":{"network":"xhttp","security":"none","xhttpSettings":{"path":"/test","headers":{"User-Agent":"test","Accept":"text/plain","X-Test":"test","Origin":"https://example.com"}}}}]}`)
	var r Runner
	if err := r.StartJSON(data); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	original := r.Instance()
	for range 30 {
		if err := r.Reload(data); err != nil {
			t.Fatal(err)
		}
		if r.Instance() != original || r.Status().Count != 1 {
			t.Fatal("identical XHTTP config restarted", r.Status().Count)
		}
	}
	changed := bytes.Replace(data, []byte(`"X-Test":"test"`), []byte(`"X-Test":"changed"`), 1)
	if err := r.Reload(changed); err != nil {
		t.Fatal(err)
	}
	if r.Status().Count != 2 {
		t.Fatal("changed header must reload exactly once")
	}
}
