package proxy

import (
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
