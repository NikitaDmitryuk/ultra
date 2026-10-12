package config

import (
	"encoding/json"
	"net/url"
	"reflect"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
)

func TestXHTTPTLSFingerprintExports(t *testing.T) {
	u := auth.User{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee", IsActive: true}
	for _, fp := range []string{"", "chrome", "firefox"} {
		t.Run("fingerprint="+fp, func(t *testing.T) {
			want := fp
			if want == "" {
				want = "chrome"
			}
			s := bridgeSpecForAntiCensorTest()
			endpoint := PublicXHTTPTLSSpec{Port: 443, ServerName: "site.example", Path: "/connect", Fingerprint: fp}
			s.PrimaryXHTTP = &PrimaryXHTTPIngress{Host: "bridge.example", BackendPort: 18080, PublicXHTTPTLSSpec: endpoint}
			primary, err := BuildSubscriptionExport(s, u, "")
			if err != nil {
				t.Fatal(err)
			}
			diagnostic, err := BuildSubscriptionExport(s, u, "xhttp-tls")
			if err != nil {
				t.Fatal(err)
			}
			experiment := BuildExperimentalExport(s, u, &ExperimentalProfile{Host: "bridge.example", Endpoint: endpoint})
			endpoint.Download = &XHTTPDownload{Address: "download.example", Port: 443, ServerName: "download.example"}
			s.PublicXHTTPTLS = &endpoint
			native := buildPublicTLSExport(s, u)
			for _, export := range []*ClientExport{primary, diagnostic, experiment, native} {
				uri, err := url.Parse(export.VLESSURI)
				if err != nil {
					t.Fatal(err)
				}
				if uri.Query().Get("fp") != want || uri.User.Username() != u.UUID {
					t.Fatal("URI fingerprint or identity mismatch")
				}
				stream := export.XRayOutboundJSON["streamSettings"].(map[string]any)
				if stream["tlsSettings"].(map[string]any)["fingerprint"] != want {
					t.Fatal("JSON fingerprint mismatch")
				}
				var extra map[string]any
				if err := json.Unmarshal([]byte(uri.Query().Get("extra")), &extra); err != nil {
					t.Fatal(err)
				}
				if download, ok := extra["downloadSettings"].(map[string]any); ok && download["tlsSettings"].(map[string]any)["fingerprint"] != want {
					t.Fatal("download fingerprint mismatch")
				}
			}
			server := publicTLSStream(s, true)
			endpoint.Fingerprint = "firefox"
			if !reflect.DeepEqual(server, publicTLSStream(s, true)) {
				t.Fatal("client fingerprint changed server transport")
			}
		})
	}
}

func TestXHTTPRejectsInvalidFingerprint(t *testing.T) {
	for _, fp := range []string{"random", "firefox\n", "unknown"} {
		endpoint := PublicXHTTPTLSSpec{Port: 443, ServerName: "site.example", Path: "/connect", Fingerprint: fp}
		if err := validatePublicEndpoint("bridge.example", &endpoint); err == nil {
			t.Fatal("invalid client fingerprint accepted")
		}
	}
}
