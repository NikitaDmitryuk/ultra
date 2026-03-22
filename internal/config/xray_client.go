package config

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
)

// ClientExport holds wire-format artifacts for compatible clients (JSON fragment and connection URI).
type ClientExport struct {
	XRayOutboundJSON map[string]any `json:"xray_client_json"`
	VLESSURI         string         `json:"vless_uri"`
}

// BuildClientExport builds a minimal outbound fragment and a connection URI for one user.
func BuildClientExport(spec *Spec, user auth.User) (*ClientExport, error) {
	w := resolveXrayWire(spec)
	enc := w.VLESSEncryption
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
								"encryption": enc,
							},
						},
					},
				},
			},
			"streamSettings": map[string]any{
				"network":  "tcp",
				"security": "none",
			},
			"tag": w.ClientOutboundTag,
		}
		uri := fmt.Sprintf("vless://%s@%s:%d?encryption=%s&security=none&type=tcp#%s",
			user.UUID, spec.PublicHost, spec.VLESSPort, url.QueryEscape(enc), url.PathEscape(user.Name))
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
							"encryption": enc,
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
		"tag": w.ClientOutboundTag,
	}

	q := url.Values{}
	q.Set("encryption", enc)
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
	w := resolveXrayWire(spec)
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
		"log":     map[string]any{"loglevel": w.ClientFullLogLevel},
		"inbounds": []any{
			map[string]any{
				"listen":   w.ClientSOCKSListen,
				"port":     w.ClientSOCKSPort,
				"protocol": "socks",
				"settings": map[string]any{"udp": true},
				"tag":      w.ClientSOCKSInboundTag,
			},
		},
		"outbounds": []any{
			exp.XRayOutboundJSON,
		},
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules": []any{
				map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": w.ClientOutboundTag},
			},
		},
	}
	b, err := json.MarshalIndent(full, "", "  ")
	if err != nil {
		return "", nil, err
	}
	return exp.VLESSURI, b, nil
}
