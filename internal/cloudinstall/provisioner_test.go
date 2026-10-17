package cloudinstall

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
)

func TestReinstallRequiresExactUnpublishedPinnedTarget(t *testing.T) {
	for _, change := range []string{"none", "published", "address", "pin", "node", "instance", "operation"} {
		op := cloud.Operation{ID: "op", ExitID: "op", InstanceID: "vm"}
		node := exits.Node{ID: "op", Address: "192.0.2.2", PinnedPeerCertSHA256: strings.Repeat("ab", 32)}
		instance := cloud.Instance{ID: "vm", IP: node.Address}
		switch change {
		case "published":
			node.Enabled = true
		case "address":
			node.Address = "192.0.2.3"
		case "pin":
			node.PinnedPeerCertSHA256 = "bad"
		case "node":
			node.ID = "other"
		case "instance":
			instance.ID = "other"
		case "operation":
			op.ExitID = "other"
		}
		if err := validateReinstallTarget(&op, node, instance); (err == nil) != (change == "none") {
			t.Fatalf("%s: %v", change, err)
		}
	}
}

func TestProvisionedExitPreservesWireTransport(t *testing.T) {
	bridge := &config.Spec{
		MimicPreset:        "steamlike",
		TunnelTLSProvision: config.TunnelTLSACME,
		SplithttpPath:      "/fixture",
		XrayWire:           &config.XrayWireSpec{SplithttpMode: "stream-one", SniffingDestOverride: []string{"tls"}},
	}
	p := &Provisioner{Bridge: bridge}
	spec := p.exitSpec(exits.Node{Port: 8443, TunnelUUID: "11111111-2222-3333-4444-555555555555"})
	if spec.TunnelTLSProvision != config.TunnelTLSSelfSigned || bridge.TunnelTLSProvision != config.TunnelTLSACME {
		t.Fatal("cloud IP exit inherited the static ACME policy or mutated the bridge")
	}
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

type failedAnsibleConfigurer struct{}

func (failedAnsibleConfigurer) Ready(context.Context) error {
	return errors.New("controller_unavailable")
}
func (failedAnsibleConfigurer) ConfigureExit(context.Context, string, string, deployansible.ExitRequest) (deployansible.Result, error) {
	panic("configuration must not run")
}

func TestAnsibleControllerPreflightPreventsPurchasePreparation(t *testing.T) {
	p := &Provisioner{
		Configurer: failedAnsibleConfigurer{},
	}
	// No API is installed: reaching cloud preparation would panic and fail this regression.
	if _, err := p.Prepare(context.Background(), &cloud.Operation{}); err == nil || err.Error() != "controller_unavailable" {
		t.Fatalf("unexpected preflight result: %v", err)
	}
}
