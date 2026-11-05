package cloudinstall

import (
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
)

func TestCloudExitInheritsPingDataplaneOnly(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		p := &Provisioner{Bridge: &config.Spec{ExitPing: enabled, HappExitPing: enabled, HappProviderID: "fixture-provider"}}
		exit := p.exitSpec(exits.Node{Port: 443, TunnelUUID: "11111111-2222-3333-4444-555555555555"})
		if exit.ExitPing != enabled || exit.HappExitPing || exit.HappProviderID != "" {
			t.Fatal("new cloud exit lost dataplane policy or inherited publication")
		}
	}
}
