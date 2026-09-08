package config

import (
	"bytes"
	"encoding/json"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"testing"
)

func TestBridgeDoHBootstrapDoesNotQueryItsOwnResolver(t *testing.T) {
	data, err := json.Marshal(map[string]any{"dns": buildBridgeDNS(), "outbounds": []any{map[string]any{"protocol": "blackhole"}}})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := core.LoadConfig("json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	instance, err := core.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = instance.Close() }()
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	resolver := instance.GetFeature(dns.ClientType()).(dns.Client)
	ips, _, err := resolver.LookupIP("common.dot.dns.yandex.net", dns.IPOption{IPv4Enable: true})
	if err != nil || len(ips) != 2 {
		t.Fatal("bootstrap attempted external DNS", err)
	}
	if ips[0].String() != "77.88.8.8" || ips[1].String() != "77.88.8.1" {
		t.Fatal("wrong bootstrap addresses")
	}
}
