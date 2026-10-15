package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
)

// SubscriptionBridge contains only public connection parameters, never server keys. Security defaults to REALITY for existing descriptors.
// This static publication list is also usable for client acceptance before clustering.
type SubscriptionBridge struct {
	ID          string `json:"id"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Transport   string `json:"transport,omitempty"`
	Security    string `json:"security,omitempty"`
	PublicKey   string `json:"public_key"`
	ServerName  string `json:"server_name"`
	ShortID     string `json:"short_id,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Path        string `json:"path,omitempty"`
}

func validateSubscriptionBridges(bridges []SubscriptionBridge) error {
	ids := map[string]bool{}
	for _, b := range bridges {
		if b.ID == "" || strings.ContainsAny(b.ID, "/ \t\r\n") || ids[b.ID] || b.Host == "" || strings.ContainsAny(b.Host, "/@?# \t\r\n") ||
			b.Port < 1 ||
			b.Port > 65535 ||
			b.ServerName == "" ||
			strings.ContainsAny(b.ServerName, "/@?# \t\r\n") {
			return fmt.Errorf("invalid or duplicate subscription bridge %q", b.ID)
		}
		if b.Transport != "" && b.Transport != "tcp" && b.Transport != "xhttp" {
			return fmt.Errorf("invalid subscription transport for %q", b.ID)
		}
		if b.Security == "tls" {
			if b.Transport != "xhttp" || b.PublicKey != "" || b.ShortID != "" || b.Path == "" || !strings.HasPrefix(b.Path, "/") ||
				strings.ContainsAny(b.Path, "?# \t\r\n") {
				return fmt.Errorf("invalid TLS subscription endpoint %q", b.ID)
			}
			ids[b.ID] = true
			continue
		}
		if b.Security != "" && b.Security != "reality" {
			return fmt.Errorf("unknown subscription security for %q", b.ID)
		}
		key, err := base64.RawURLEncoding.DecodeString(b.PublicKey)
		if err != nil || len(key) != 32 {
			return fmt.Errorf("invalid subscription public key for %q", b.ID)
		}
		shortID, err := hex.DecodeString(b.ShortID)
		if err != nil || len(shortID) > 8 {
			return fmt.Errorf("invalid subscription short ID for %q", b.ID)
		}
		ids[b.ID] = true
	}
	return nil
}

// BuildHappProfile builds a complete Xray profile whose credentials select the
// same server-side route on every bridge. No direct client outbound is installed.
func BuildHappProfile(spec *Spec, user auth.User, name string) (map[string]any, error) {
	if err := validateSubscriptionBridges(spec.SubscriptionBridges); err != nil {
		return nil, err
	}
	outbounds := []any{map[string]any{"tag": "block", "protocol": "blackhole"}}
	add := func(s *Spec, tag string) error {
		if !s.PrimaryXHTTPIsPublished() && !s.DevMode && len(s.Reality.ServerNames) == 0 {
			return fmt.Errorf("subscription: REALITY server name is required")
		}
		export, err := BuildSubscriptionExport(s, user, "")
		if err != nil {
			return err
		}
		export.XRayOutboundJSON["tag"] = tag
		outbounds = append(outbounds, export.XRayOutboundJSON)
		return nil
	}
	if len(spec.SubscriptionBridges) == 0 {
		if err := add(spec, "bridge-primary"); err != nil {
			return nil, err
		}
	}
	for _, b := range spec.SubscriptionBridges {
		child := *spec
		child.PrimaryXHTTP = nil
		child.PublicXHTTPTLS = nil
		child.LegacyPublicEnabled = BoolPtr(true)
		child.PublicEntries = nil
		child.SubscriptionBridges = nil
		child.PublicHost, child.VLESSPort = b.Host, b.Port
		child.Reality = RealitySpec{
			PublicKey:   b.PublicKey,
			ServerNames: []string{b.ServerName},
			ShortIDs:    []string{b.ShortID},
			Fingerprint: b.Fingerprint,
		}
		child.AntiCensor = nil
		child.SplithttpPath = b.Path
		if b.Transport == "xhttp" {
			child.AntiCensor = &AntiCensorSpec{PublicXHTTPPort: b.Port}
		}
		if b.Security == "tls" {
			child.AntiCensor = nil
			child.PrimaryXHTTP = &PrimaryXHTTPIngress{
				Host:      b.Host,
				Published: BoolPtr(true),
				PublicXHTTPTLSSpec: PublicXHTTPTLSSpec{
					Port:        b.Port,
					ServerName:  b.ServerName,
					Path:        b.Path,
					Fingerprint: b.Fingerprint,
					Mode:        "stream-up",
				},
			}
		}
		if err := add(&child, "bridge-"+b.ID); err != nil {
			return nil, err
		}
	}
	return map[string]any{
		"remarks": name,
		"log":     map[string]any{"loglevel": "warning"},
		"inbounds": []any{
			map[string]any{
				"listen":   "127.0.0.1",
				"port":     10808,
				"protocol": "socks",
				"settings": map[string]any{"udp": true},
				"tag":      "socks",
			},
		},
		"outbounds": outbounds,
		"burstObservatory": map[string]any{
			"subjectSelector": []string{"bridge-"},
			"pingConfig": map[string]any{
				"destination": "https://www.google.com/generate_204",
				"interval":    "10s",
				"sampling":    1,
				"timeout":     "5s",
				"httpMethod":  "GET",
			},
		},
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"balancers": []any{
				map[string]any{
					"tag":         "bridges",
					"selector":    []string{"bridge-"},
					"fallbackTag": "block",
					"strategy":    map[string]any{"type": "leastPing"},
				},
			},
			"rules": []any{map[string]any{"type": "field", "network": "tcp,udp", "balancerTag": "bridges"}},
		},
	}, nil
}

// BuildHappFaultProfiles is a restricted acceptance export. Unreachable .invalid
// hosts affect only these client profiles, never production listeners or routes.
func BuildHappFaultProfiles(spec *Spec, user auth.User) ([]map[string]any, error) {
	if len(spec.SubscriptionBridges) != 2 {
		return nil, fmt.Errorf("fault preview requires two endpoints")
	}
	primary, reserve := -1, -1
	for i, b := range spec.SubscriptionBridges {
		switch b.Security {
		case "tls":
			primary = i
		case "reality", "":
			reserve = i
		}
	}
	if primary < 0 || reserve < 0 {
		return nil, fmt.Errorf("fault preview requires TLS and REALITY")
	}
	profiles := make([]map[string]any, 0, 4)
	for _, test := range []struct {
		name                     string
		primaryDown, reserveDown bool
	}{
		{"Тест · оба входа", false, false},
		{"Тест · основной недоступен", true, false},
		{"Тест · резерв недоступен", false, true},
		{"Тест · оба недоступны", true, true},
	} {
		copySpec := *spec
		copySpec.SubscriptionBridges = append([]SubscriptionBridge(nil), spec.SubscriptionBridges...)
		if test.primaryDown {
			copySpec.SubscriptionBridges[primary].Host = "primary-unavailable.invalid"
		}
		if test.reserveDown {
			copySpec.SubscriptionBridges[reserve].Host = "reserve-unavailable.invalid"
		}
		profile, err := BuildHappProfile(&copySpec, user, test.name)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, profile)
	}
	return profiles, nil
}
