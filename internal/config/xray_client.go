package config

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
)

const (
	ClientProfileFastTCPReality       = "fast_tcp_reality"
	ClientProfileFallbackXHTTPReality = "fallback_xhttp_reality"
)

// ClientExport holds wire-format artifacts for compatible clients (JSON fragment and connection URI).
type ClientExport struct {
	XRayOutboundJSON map[string]any `json:"xray_client_json"`
	VLESSURI         string         `json:"vless_uri"`
}

// ClientProfileExport describes one importable client profile. Legacy clients can keep using
// ClientExport.VLESSURI; newer UIs can surface this list as primary/fallback choices.
type ClientProfileExport struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	Transport        string         `json:"transport"`
	XRayOutboundJSON map[string]any `json:"xray_client_json"`
	VLESSURI         string         `json:"vless_uri"`
	FullConfigBase64 string         `json:"full_xray_config_base64"`
}

// BuildClientExport builds a minimal outbound fragment and a connection URI for one user.
func vlessUserFields(spec *Spec, userUUID string) map[string]any {
	u := map[string]any{
		"id":         userUUID,
		"encryption": resolveXrayWire(spec).VLESSEncryption,
	}
	if flow := spec.PublicVLESSFlow(); flow != "" {
		u["flow"] = flow
	}
	return u
}

func vlessUserFieldsNoFlow(spec *Spec, userUUID string) map[string]any {
	return map[string]any{
		"id":         userUUID,
		"encryption": resolveXrayWire(spec).VLESSEncryption,
	}
}

func clientRealityFingerprint(spec *Spec) string {
	if spec.Reality.Fingerprint != "" {
		return spec.Reality.Fingerprint
	}
	if spec.AntiCensor != nil && len(spec.AntiCensor.RealityFingerprints) > 0 {
		return spec.AntiCensor.RealityFingerprints[0]
	}
	return "chrome"
}

func legacySpiderX(spec *Spec) string {
	if spec.Reality.SpiderX != "" {
		return spec.Reality.SpiderX
	}
	return "/"
}

func profileSpiderX(user auth.User, profileID string) string {
	seed := user.UUID + ":" + profileID
	sum := sha256.Sum256([]byte(seed))
	return "/assets/" + base64.RawURLEncoding.EncodeToString(sum[:9])
}

func fallbackXHTTPPort(spec *Spec) int {
	if spec.AntiCensor != nil && spec.AntiCensor.PublicXHTTPPort > 0 {
		return spec.AntiCensor.PublicXHTTPPort
	}
	return spec.VLESSPort
}

func fallbackXHTTPPadding(spec *Spec) string {
	profile := AntiCensorProfileBalanced
	if spec.AntiCensor != nil && strings.TrimSpace(spec.AntiCensor.Profile) != "" {
		profile = strings.TrimSpace(spec.AntiCensor.Profile)
	}
	switch profile {
	case AntiCensorProfileFast:
		return "0-64"
	case AntiCensorProfileStealth:
		return "64-512"
	default:
		return "0-128"
	}
}

func fallbackXHTTPPath(spec *Spec) string {
	if spec.SplithttpPath != "" {
		return spec.SplithttpPath
	}
	return "/xhttp"
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
							vlessUserFields(spec, user.UUID),
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
		q := url.Values{}
		q.Set("encryption", enc)
		q.Set("security", "none")
		q.Set("type", "tcp")
		uri := fmt.Sprintf("vless://%s@%s:%d?%s#%s",
			user.UUID, spec.PublicHost, spec.VLESSPort, q.Encode(), url.PathEscape(user.Name))
		return &ClientExport{XRayOutboundJSON: frag, VLESSURI: uri}, nil
	}

	sni := spec.Reality.ServerNames[0]
	fp := clientRealityFingerprint(spec)
	sid := ""
	if len(spec.Reality.ShortIDs) > 0 {
		sid = spec.Reality.ShortIDs[0]
	}
	spx := legacySpiderX(spec)

	frag := map[string]any{
		"protocol": "vless",
		"settings": map[string]any{
			"vnext": []any{
				map[string]any{
					"address": spec.PublicHost,
					"port":    spec.VLESSPort,
					"users": []any{
						vlessUserFields(spec, user.UUID),
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
	if flow := spec.PublicVLESSFlow(); flow != "" {
		q.Set("flow", flow)
	}
	name := user.Name
	if name == "" {
		name = "user"
	}
	uri := fmt.Sprintf("vless://%s@%s:%d?%s#%s",
		user.UUID, spec.PublicHost, spec.VLESSPort, q.Encode(), url.PathEscape(name))

	return &ClientExport{XRayOutboundJSON: frag, VLESSURI: uri}, nil
}

func fullClientXRayJSONForOutbound(spec *Spec, user auth.User, outbound map[string]any) ([]byte, error) {
	w := resolveXrayWire(spec)
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
			outbound,
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
		return nil, err
	}
	return b, nil
}

// FullClientXRayJSON returns a minimal runnable config document for a single client (file import).
func FullClientXRayJSON(spec *Spec, user auth.User) (vlessURI string, jsonBytes []byte, err error) {
	exp, err := BuildClientExport(spec, user)
	if err != nil {
		return "", nil, err
	}
	b, err := fullClientXRayJSONForOutbound(spec, user, exp.XRayOutboundJSON)
	if err != nil {
		return "", nil, err
	}
	return exp.VLESSURI, b, nil
}

func buildFallbackXHTTPExport(spec *Spec, user auth.User) (*ClientExport, error) {
	w := resolveXrayWire(spec)
	enc := w.VLESSEncryption
	if spec.DevMode {
		return BuildClientExport(spec, user)
	}
	sni := spec.Reality.ServerNames[0]
	fp := clientRealityFingerprint(spec)
	sid := ""
	if len(spec.Reality.ShortIDs) > 0 {
		sid = spec.Reality.ShortIDs[0]
	}
	spx := profileSpiderX(user, ClientProfileFallbackXHTTPReality)
	path := fallbackXHTTPPath(spec)
	padding := fallbackXHTTPPadding(spec)
	frag := map[string]any{
		"protocol": "vless",
		"settings": map[string]any{
			"vnext": []any{
				map[string]any{
					"address": spec.PublicHost,
					"port":    fallbackXHTTPPort(spec),
					"users": []any{
						vlessUserFieldsNoFlow(spec, user.UUID),
					},
				},
			},
		},
		"streamSettings": map[string]any{
			"network":  "xhttp",
			"security": "reality",
			"realitySettings": map[string]any{
				"show":        false,
				"fingerprint": fp,
				"serverName":  sni,
				"publicKey":   spec.Reality.PublicKey,
				"shortId":     sid,
				"spiderX":     spx,
			},
			"xhttpSettings": map[string]any{
				"path":         path,
				"mode":         "auto",
				"xPaddingSize": padding,
			},
		},
		"tag": w.ClientOutboundTag,
	}

	q := url.Values{}
	q.Set("encryption", enc)
	q.Set("security", "reality")
	q.Set("type", "xhttp")
	q.Set("fp", fp)
	q.Set("sni", sni)
	q.Set("pbk", spec.Reality.PublicKey)
	q.Set("sid", sid)
	q.Set("spx", spx)
	q.Set("path", path)
	q.Set("mode", "auto")
	name := user.Name
	if name == "" {
		name = "user"
	}
	uri := fmt.Sprintf("vless://%s@%s:%d?%s#%s",
		user.UUID, spec.PublicHost, fallbackXHTTPPort(spec), q.Encode(), url.PathEscape(name+" fallback"))
	return &ClientExport{XRayOutboundJSON: frag, VLESSURI: uri}, nil
}

// BuildClientProfiles returns the legacy primary profile plus a prepared XHTTP fallback profile.
func BuildClientProfiles(spec *Spec, user auth.User) ([]ClientProfileExport, error) {
	fast, err := BuildClientExport(spec, user)
	if err != nil {
		return nil, err
	}
	fastJSON, err := fullClientXRayJSONForOutbound(spec, user, fast.XRayOutboundJSON)
	if err != nil {
		return nil, err
	}
	fallback, err := buildFallbackXHTTPExport(spec, user)
	if err != nil {
		return nil, err
	}
	fallbackJSON, err := fullClientXRayJSONForOutbound(spec, user, fallback.XRayOutboundJSON)
	if err != nil {
		return nil, err
	}
	return []ClientProfileExport{
		{
			ID:               ClientProfileFastTCPReality,
			Name:             "Fast TCP REALITY",
			Transport:        "tcp",
			XRayOutboundJSON: fast.XRayOutboundJSON,
			VLESSURI:         fast.VLESSURI,
			FullConfigBase64: base64.StdEncoding.EncodeToString(fastJSON),
		},
		{
			ID:               ClientProfileFallbackXHTTPReality,
			Name:             "Fallback XHTTP REALITY",
			Transport:        "xhttp",
			XRayOutboundJSON: fallback.XRayOutboundJSON,
			VLESSURI:         fallback.VLESSURI,
			FullConfigBase64: base64.StdEncoding.EncodeToString(fallbackJSON),
		},
	}, nil
}
