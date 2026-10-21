package main

import (
	"encoding/json"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/config"
)

func TestManagedTLSDesiredIdentityBindsDomain(t *testing.T) {
	_, r := runtimeHostFixture(t)
	legacy, err := runtimeHostDesiredIdentity(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Features.MainExitDomain = "tunnel.example.com"
	managed, err := runtimeHostDesiredIdentity(r)
	if err != nil || managed == legacy {
		t.Fatal("managed domain was not bound to desired identity")
	}
	r.Features.MainExitDomain = "other.example.com"
	changed, err := runtimeHostDesiredIdentity(r)
	if err != nil || changed == managed {
		t.Fatal("changed managed domain retained desired identity")
	}
}

func TestManagedTLSInstalledIdentityBindsPolicy(t *testing.T) {
	s, _ := runtimeHostFixture(t)
	image, err := s.image(s.path(runtimeHostFiles[0]))
	if err != nil {
		t.Fatal(err)
	}
	var original map[string]json.RawMessage
	if err = json.Unmarshal(image.Data, &original); err != nil {
		t.Fatal(err)
	}
	original["tunnel_tls_provision"], _ = json.Marshal(config.TunnelTLSACME)
	original["splithttp_host"] = json.RawMessage(`"tunnel.example.com"`)
	baselineRaw, _ := json.Marshal(original)
	baseline, err := runtimeHostInstalledIdentity(baselineRaw)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"tunnel_tls_provision", "mimic_preset", "tunnel_transport", "splithttp_host", "splithttp_path", "splithttp_tls", "exit_cert"} {
		t.Run(key, func(t *testing.T) {
			var changed map[string]json.RawMessage
			_ = json.Unmarshal(baselineRaw, &changed)
			delete(changed, key)
			raw, _ := json.Marshal(changed)
			digest, err := runtimeHostInstalledIdentity(raw)
			if err != nil || digest == baseline {
				t.Fatal("removed TLS policy field retained installed identity")
			}
		})
	}
	// Future raw TLS policy fields also belong to immutable managed identity.
	original["splithttp_tls"] = json.RawMessage(`{"server_name":"tunnel.example.com","future_policy":true}`)
	raw, _ := json.Marshal(original)
	changed, err := runtimeHostInstalledIdentity(raw)
	if err != nil || changed == baseline {
		t.Fatal("unknown TLS policy retained installed identity")
	}
}
