package config

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/NikitaDmitryuk/ultra/auth"
)

// ClientExport holds wire-format artifacts for compatible clients (JSON fragment and connection URI).
type ClientExport struct {
	XRayOutboundJSON map[string]any `json:"xray_client_json"`
	VLESSURI         string         `json:"vless_uri"`
}

// BuildClientExport builds a minimal outbound fragment and a connection URI for one user.
func BuildClientExport(spec *Spec, user auth.User) (*ClientExport, error) {
	if spec.DevMode {
		frag := map[string]any{
			"protocol": "vless",
			"settings": map[string]any{
				"vnext": []any{
					map[string]any{
						"address": spec.PublicHost,
						"port":    spec.VLESSPort,
						"users": []any{
							map[string]any{
								"id":         user.UUID,
								"encryption": "none",
							},
						},
					},
				},
			},
			"streamSettings": map[string]any{
				"network":  "tcp",
				"security": "none",
			},
			"tag": "proxy",
		}
		uri := fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=none&type=tcp#%s",
			user.UUID, spec.PublicHost, spec.VLESSPort, url.PathEscape(user.Name))
		return &ClientExport{XRayOutboundJSON: frag, VLESSURI: uri}, nil
	}

	sni := spec.Reality.ServerNames[0]
	fp := spec.Reality.Fingerprint
	if fp == "" {
		fp = "chrome"
	}
	sid := ""
	if len(spec.Reality.ShortIDs) > 0 {
		sid = spec.Reality.ShortIDs[0]
	}
	spx := spec.Reality.SpiderX
	if spx == "" {
		spx = "/"
	}

	frag := map[string]any{
		"protocol": "vless",
		"settings": map[string]any{
			"vnext": []any{
				map[string]any{
					"address": spec.PublicHost,
					"port":    spec.VLESSPort,
					"users": []any{
						map[string]any{
							"id":         user.UUID,
							"encryption": "none",
						},
					},
				},
			},
		},
		"streamSettings": map[string]any{
			"network":  "tcp",
			"security": "reality",
			"realitySettings": map[string]any{
				"show":        false,
				"fingerprint": fp,
				"serverName":  sni,
				"publicKey":   spec.Reality.PublicKey,
				"shortId":     sid,
				"spiderX":     spx,
			},
		},
		"tag": "proxy",
	}

	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("security", "reality")
	q.Set("type", "tcp")
	q.Set("fp", fp)
	q.Set("sni", sni)
	q.Set("pbk", spec.Reality.PublicKey)
	q.Set("sid", sid)
	q.Set("spx", spx)
	name := user.Name
	if name == "" {
		name = "user"
	}
	uri := fmt.Sprintf("vless://%s@%s:%d?%s#%s",
		user.UUID, spec.PublicHost, spec.VLESSPort, q.Encode(), url.PathEscape(name))

	return &ClientExport{XRayOutboundJSON: frag, VLESSURI: uri}, nil
}

// FullClientXRayJSON returns a minimal runnable config document for a single client (file import).
func FullClientXRayJSON(spec *Spec, user auth.User) (vlessURI string, jsonBytes []byte, err error) {
	exp, err := BuildClientExport(spec, user)
	if err != nil {
		return "", nil, err
	}
	remarks := user.Name
	if remarks == "" {
		remarks = "ultra-relay"
	}
	full := map[string]any{
		"remarks": remarks,
		"log":     map[string]any{"loglevel": "warning"},
		"inbounds": []any{
			map[string]any{
				"listen":   "127.0.0.1",
				"port":     10808,
				"protocol": "socks",
				"settings": map[string]any{"udp": true},
				"tag":      "socks-in",
			},
		},
		"outbounds": []any{
			exp.XRayOutboundJSON,
		},
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules": []any{
				map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "proxy"},
			},
		},
	}
	b, err := json.MarshalIndent(full, "", "  ")
	if err != nil {
		return "", nil, err
	}
	return exp.VLESSURI, b, nil
}
