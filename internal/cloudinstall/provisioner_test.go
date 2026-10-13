package cloudinstall

import (
	"encoding/json"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"testing"
)

func TestProvisionedExitPreservesWireTransport(t *testing.T) {
	bridge := &config.Spec{MimicPreset: "steamlike", SplithttpPath: "/fixture", XrayWire: &config.XrayWireSpec{SplithttpMode: "stream-one", SniffingDestOverride: []string{"tls"}}}
	p := &Provisioner{Bridge: bridge}
	spec := p.exitSpec(exits.Node{Port: 8443, TunnelUUID: "11111111-2222-3333-4444-555555555555"})
	strategy, _ := mimic.New(bridge.MimicPreset)
	raw, err := config.BuildExitXRayJSON(&spec, strategy, "none")
	if err != nil {
		t.Fatal(err)
	}
	var rendered struct {
		Inbounds []struct {
			Stream struct {
				Split struct {
					Mode string `json:"mode"`
				} `json:"splithttpSettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if err = json.Unmarshal(raw, &rendered); err != nil {
		t.Fatal(err)
	}
	if got := rendered.Inbounds[0].Stream.Split.Mode; got != "stream-one" {
		t.Fatalf("provisioned tunnel mode = %q, want bridge stream-one", got)
	}
	spec.XrayWire.SniffingDestOverride[0] = "http"
	if bridge.XrayWire.SniffingDestOverride[0] != "tls" {
		t.Fatal("exit aliases bridge wire settings")
	}
}
