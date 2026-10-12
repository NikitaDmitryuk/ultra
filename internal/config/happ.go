package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
)

// SubscriptionBridge contains only public connection parameters, never server keys.
// This static publication list is also usable for client acceptance before clustering.
type SubscriptionBridge struct {
	ID          string `json:"id"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Transport   string `json:"transport,omitempty"`
	PublicKey   string `json:"public_key"`
	ServerName  string `json:"server_name"`
	ShortID     string `json:"short_id,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Path        string `json:"path,omitempty"`
}

func validateSubscriptionBridges(bridges []SubscriptionBridge) error {
	ids := map[string]bool{}
	for _, b := range bridges {
		if b.ID == "" || strings.ContainsAny(b.ID, "/ \t\r\n") || ids[b.ID] || b.Host == "" || strings.ContainsAny(b.Host, "/@?# \t\r\n") || b.Port < 1 || b.Port > 65535 || b.PublicKey == "" || b.ServerName == "" {
			return fmt.Errorf("invalid or duplicate subscription bridge %q", b.ID)
		}
		if b.Transport != "" && b.Transport != "tcp" && b.Transport != "xhttp" {
			return fmt.Errorf("invalid subscription transport for %q", b.ID)
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
	if spec.PrimaryXHTTPIsPublished() && len(spec.SubscriptionBridges) > 0 {
		return nil, fmt.Errorf("primary XHTTP cannot use REALITY subscription bridges")
	}
	for _, b := range spec.SubscriptionBridges {
		child := *spec
		child.PublicHost, child.VLESSPort = b.Host, b.Port
		child.Reality = RealitySpec{PublicKey: b.PublicKey, ServerNames: []string{b.ServerName}, ShortIDs: []string{b.ShortID}, Fingerprint: b.Fingerprint}
		child.AntiCensor = nil
		child.SplithttpPath = b.Path
		if b.Transport == "xhttp" {
			child.AntiCensor = &AntiCensorSpec{PublicXHTTPPort: b.Port}
		}
		if err := add(&child, "bridge-"+b.ID); err != nil {
			return nil, err
		}
	}
	return map[string]any{
		"remarks":   name,
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  []any{map[string]any{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": map[string]any{"udp": true}, "tag": "socks"}},
		"outbounds": outbounds,
		"burstObservatory": map[string]any{
			"subjectSelector": []string{"bridge-"},
			"pingConfig":      map[string]any{"destination": "https://www.google.com/generate_204", "interval": "10s", "sampling": 1, "timeout": "5s", "httpMethod": "GET"},
		},
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"balancers":      []any{map[string]any{"tag": "bridges", "selector": []string{"bridge-"}, "fallbackTag": "block", "strategy": map[string]any{"type": "leastPing"}}},
			"rules":          []any{map[string]any{"type": "field", "network": "tcp,udp", "balancerTag": "bridges"}},
		},
	}, nil
}
