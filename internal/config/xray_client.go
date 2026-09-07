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
	ClientAPIBaseURL string         `json:"client_api_base_url,omitempty"`
}

// ClientProfileExport describes one importable client profile. Legacy clients can keep using
// ClientExport.VLESSURI; newer UIs can surface this list as primary/fallback choices.
type ClientProfileExport struct {
	LocationID       string         `json:"location_id,omitempty"`
	RouteID          string         `json:"route_id,omitempty"`
	EntryID          string         `json:"entry_id"`
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	Transport        string         `json:"transport"`
	XRayOutboundJSON map[string]any `json:"xray_client_json"`
	VLESSURI         string         `json:"vless_uri"`
	FullConfigBase64 string         `json:"full_xray_config_base64"`
	ClientAPIBaseURL string         `json:"client_api_base_url,omitempty"`
}

func addClientAPIParam(vlessURI, clientAPIBaseURL string) string {
	clientAPIBaseURL = strings.TrimSpace(clientAPIBaseURL)
	if clientAPIBaseURL == "" || vlessURI == "" {
		return vlessURI
	}
	u, err := url.Parse(vlessURI)
	if err != nil {
		return vlessURI
	}
	q := u.Query()
	q.Set("api", clientAPIBaseURL)
	u.RawQuery = q.Encode()
	return u.String()
}

func WithClientAPIBaseURL(exp *ClientExport, clientAPIBaseURL string) *ClientExport {
	if exp == nil {
		return nil
	}
	cp := *exp
	cp.ClientAPIBaseURL = strings.TrimSpace(clientAPIBaseURL)
	cp.VLESSURI = addClientAPIParam(cp.VLESSURI, cp.ClientAPIBaseURL)
	return &cp
}

func WithClientAPIBaseURLProfiles(profiles []ClientProfileExport, clientAPIBaseURL string) []ClientProfileExport {
	if strings.TrimSpace(clientAPIBaseURL) == "" {
		return profiles
	}
	out := make([]ClientProfileExport, len(profiles))
	copy(out, profiles)
	for i := range out {
		out[i].ClientAPIBaseURL = strings.TrimSpace(clientAPIBaseURL)
		out[i].VLESSURI = addClientAPIParam(out[i].VLESSURI, out[i].ClientAPIBaseURL)
	}
	return out
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

func fallbackXHTTPPadding(spec *Spec) string { return effectivePadding(spec) }

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
				"path":          path,
				"mode":          "auto",
				"xPaddingBytes": padding,
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
	extra, _ := json.Marshal(map[string]any{"xPaddingBytes": padding})
	q.Set("extra", string(extra))
	name := user.Name
	if name == "" {
		name = "user"
	}
	uri := fmt.Sprintf("vless://%s@%s:%d?%s#%s",
		user.UUID, spec.PublicHost, fallbackXHTTPPort(spec), q.Encode(), url.PathEscape(name+" fallback"))
	return &ClientExport{XRayOutboundJSON: frag, VLESSURI: uri}, nil
}

// BuildClientProfiles exports only configured listeners. Legacy TCP fields remain unchanged.
func buildTransportProfiles(spec *Spec, user auth.User) ([]ClientProfileExport, error) {
	fast, err := BuildClientExport(spec, user)
	if err != nil {
		return nil, err
	}
	profiles := []ClientProfileExport{}
	add := func(id, name, transport string, exp *ClientExport) error {
		full, err := fullClientXRayJSONForOutbound(spec, user, exp.XRayOutboundJSON)
		if err != nil {
			return err
		}
		profiles = append(profiles, ClientProfileExport{EntryID: "primary", ID: id, Name: name, Transport: transport, XRayOutboundJSON: exp.XRayOutboundJSON, VLESSURI: exp.VLESSURI, FullConfigBase64: base64.StdEncoding.EncodeToString(full)})
		return nil
	}
	if err := add(ClientProfileFastTCPReality, "Основной · TCP REALITY", "tcp", fast); err != nil {
		return nil, err
	}
	if spec.AntiCensor != nil && spec.AntiCensor.PublicXHTTPPort > 0 && !spec.DevMode {
		fallback, err := buildFallbackXHTTPExport(spec, user)
		if err != nil {
			return nil, err
		}
		if err := add(ClientProfileFallbackXHTTPReality, "Резерв · XHTTP REALITY", "xhttp", fallback); err != nil {
			return nil, err
		}
	}
	if spec.PublicXHTTPTLS != nil && !spec.DevMode {
		exp := buildPublicTLSExport(spec, user)
		if err := add("fallback_xhttp_tls", "Резерв · XHTTP TLS", "xhttp", exp); err != nil {
			return nil, err
		}
	}
	for _, entry := range spec.PublicEntries {
		child := *spec
		child.PublicEntries = nil
		child.PublicHost = entry.Host
		child.VLESSPort = entry.TCPPort
		anti := AntiCensorSpec{}
		if spec.AntiCensor != nil {
			anti = *spec.AntiCensor
		}
		anti.PublicXHTTPPort = entry.XHTTPRealityPort
		child.AntiCensor = &anti
		child.PublicXHTTPTLS = nil
		if entry.XHTTPTLSPort > 0 && spec.PublicXHTTPTLS != nil {
			tls := *spec.PublicXHTTPTLS
			tls.Port = entry.XHTTPTLSPort
			child.PublicXHTTPTLS = &tls
		}
		extra, err := buildTransportProfiles(&child, user)
		if err != nil {
			return nil, err
		}
		for _, p := range extra {
			p.EntryID = entry.ID
			p.ID = entry.ID + "/" + p.ID
			p.Name = entry.ID + " · " + p.Name
			uri, err := url.Parse(p.VLESSURI)
			if err != nil {
				return nil, err
			}
			uri.Fragment = entry.ID + " · " + uri.Fragment
			p.VLESSURI = uri.String()
			profiles = append(profiles, p)
		}
	}
	return profiles, nil
}

// BuildClientProfiles keeps legacy IDs and appends stable per-location credentials.
func BuildClientProfiles(spec *Spec, user auth.User) ([]ClientProfileExport, error) {
	base, e := buildTransportProfiles(spec, user)
	if e != nil {
		return nil, e
	}
	decorate := func(p *ClientProfileExport, prefix string) {
		p.Name = prefix + " · " + p.Name
		uri, err := url.Parse(p.VLESSURI)
		if err == nil {
			uri.Fragment = p.Name
			p.VLESSURI = uri.String()
		}
	}
	for i := range base {
		base[i].RouteID = "default"
		if len(user.Routes) > 0 {
			decorate(&base[i], "Автоматически · выбор из Mini App")
		}
	}
	for _, route := range user.Routes {
		if !route.Published {
			continue
		}
		alias := user
		alias.UUID = route.UUID
		alias.Routes = nil
		profiles, err := buildTransportProfiles(spec, alias)
		if err != nil {
			return nil, err
		}
		for i := range profiles {
			profiles[i].ID = "location/" + route.LocationID + "/" + profiles[i].ID
			profiles[i].LocationID = route.LocationID
			profiles[i].RouteID = route.LocationID
			decorate(&profiles[i], route.Name)
		}
		base = append(base, profiles...)
	}
	return base, nil
}

// BuildSubscriptionExport selects one configured transport without expanding routes
// or rendering full client configs. Legacy exports and listeners remain unchanged.
func BuildSubscriptionExport(spec *Spec, user auth.User) (*ClientExport, error) {
	if !spec.DevMode && spec.AntiCensor != nil && spec.AntiCensor.PublicXHTTPPort > 0 {
		if len(spec.Reality.ServerNames) == 0 {
			return nil, fmt.Errorf("subscription: REALITY server name is required")
		}
		return buildFallbackXHTTPExport(spec, user)
	}
	return BuildClientExport(spec, user)
}
