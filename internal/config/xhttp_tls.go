package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/xtls/xray-core/infra/conf"
)

// PublicXHTTPTLSSpec is an opt-in listener independent of existing REALITY credentials.
type PublicXHTTPTLSSpec struct {
	Port            int              `json:"port"`
	ServerName      string           `json:"server_name"`
	CertificateFile string           `json:"certificate_file"`
	KeyFile         string           `json:"key_file"`
	Path            string           `json:"path"`
	Mode            string           `json:"mode,omitempty"`
	XMUX            *conf.XmuxConfig `json:"xmux,omitempty"`
	Download        *XHTTPDownload   `json:"download,omitempty"`
}
type XHTTPDownload struct {
	Address    string `json:"address"`
	Port       int    `json:"port"`
	ServerName string `json:"server_name"`
}

func publicTLSSettings(s *Spec, server bool) map[string]any {
	t := s.PublicXHTTPTLS
	mode := t.Mode
	if mode == "" {
		mode = "stream-up"
	}
	settings := map[string]any{"path": t.Path, "mode": mode, "xPaddingBytes": effectivePadding(s)}
	if mode == "packet-up" && s.AntiCensor != nil && s.AntiCensor.SplitHTTPMaxChunkKB > 0 {
		settings["scMaxEachPostBytes"] = s.AntiCensor.SplitHTTPMaxChunkKB * 1024
	}
	if !server && t.XMUX != nil {
		settings["xmux"] = t.XMUX
	}
	if !server && t.Download != nil {
		d := t.Download
		settings["downloadSettings"] = map[string]any{"address": d.Address, "port": d.Port, "network": "xhttp", "security": "tls",
			"tlsSettings":   map[string]any{"serverName": d.ServerName, "alpn": []string{"h2"}, "fingerprint": "chrome"},
			"xhttpSettings": map[string]any{"path": t.Path, "mode": mode, "xPaddingBytes": effectivePadding(s)}}
	}
	return settings
}
func publicTLSStream(s *Spec, server bool) map[string]any {
	t := s.PublicXHTTPTLS
	tls := map[string]any{"serverName": t.ServerName, "alpn": []string{"h2"}}
	if server {
		tls["certificates"] = []any{map[string]any{"certificateFile": t.CertificateFile, "keyFile": t.KeyFile}}
	} else {
		tls["fingerprint"] = "chrome"
	}
	return map[string]any{"network": "xhttp", "security": "tls", "tlsSettings": tls, "xhttpSettings": publicTLSSettings(s, server)}
}
func buildPublicTLSExport(s *Spec, u auth.User) *ClientExport {
	t := s.PublicXHTTPTLS
	w := resolveXrayWire(s)
	outbound := map[string]any{"tag": w.ClientOutboundTag, "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": s.PublicHost, "port": t.Port, "users": []any{vlessUserFieldsNoFlow(s, u.UUID)}}}}, "streamSettings": publicTLSStream(s, false)}
	extra, _ := json.Marshal(publicTLSSettings(s, false))
	mode := t.Mode
	if mode == "" {
		mode = "stream-up"
	}
	q := url.Values{"type": {"xhttp"}, "security": {"tls"}, "encryption": {"none"}, "sni": {t.ServerName}, "fp": {"chrome"}, "alpn": {"h2"}, "path": {t.Path}, "mode": {mode}, "extra": {string(extra)}}
	uri := fmt.Sprintf("vless://%s@%s?%s#%s", u.UUID, net.JoinHostPort(s.PublicHost, strconv.Itoa(t.Port)), q.Encode(), url.PathEscape(u.Name+" XHTTP TLS"))
	return &ClientExport{VLESSURI: uri, XRayOutboundJSON: outbound}
}

// PublicEntry describes an explicitly provisioned TCP passthrough, not another database owner.
type PublicEntry struct {
	ID               string `json:"id"`
	Host             string `json:"host"`
	TCPPort          int    `json:"tcp_port"`
	XHTTPRealityPort int    `json:"xhttp_reality_port,omitempty"`
	XHTTPTLSPort     int    `json:"xhttp_tls_port,omitempty"`
}
