package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
)

// PrimaryXHTTPIngress separates the public HTTPS endpoint from its loopback backend.
type PrimaryXHTTPIngress struct {
	PublicXHTTPTLSSpec
	Host        string `json:"host"`
	BackendPort int    `json:"backend_port"`
	Published   *bool  `json:"published,omitempty"`
}

// ExperimentalProfile contains publication metadata, not certificates or server credentials.
type ExperimentalProfile struct {
	Host       string             `json:"host"`
	Endpoint   PublicXHTTPTLSSpec `json:"endpoint"`
	StatusPort int                `json:"status_port"`
}

// ExperimentalTransportSpec runs only a fixed transport gateway, without application workers.
type ExperimentalTransportSpec struct {
	Profile     ExperimentalProfile `json:"profile"`
	BackendPort int                 `json:"backend_port"`
}

func (s *Spec) PrimaryXHTTPIsPublished() bool {
	return s.PrimaryXHTTP != nil && (s.PrimaryXHTTP.Published == nil || *s.PrimaryXHTTP.Published)
}

func (s *Spec) LegacyPublicIsEnabled() bool {
	return s.LegacyPublicEnabled == nil || *s.LegacyPublicEnabled
}

func validatePublicEndpoint(host string, t *PublicXHTTPTLSSpec) error {
	if err := t.validateFingerprint(); err != nil {
		return err
	}
	if host == "" || strings.ContainsAny(host, "/@?# \t\r\n") || t.Port < 1 || t.Port > 65535 || t.ServerName == "" ||
		net.ParseIP(t.ServerName) != nil ||
		strings.ContainsAny(t.ServerName, "/: \t\r\n") {
		return fmt.Errorf("invalid public XHTTP endpoint")
	}
	if t.Path == "" || !strings.HasPrefix(t.Path, "/") || strings.ContainsAny(t.Path, "?# \t\r\n") {
		return fmt.Errorf("invalid XHTTP path")
	}
	if t.Mode != "" && t.Mode != "stream-up" && t.Mode != "packet-up" {
		return fmt.Errorf("invalid XHTTP mode")
	}
	return nil
}

func (s *Spec) validatePrimaryIngress() error {
	if s.PrimaryXHTTP == nil && s.ExperimentalProfileFile == "" && s.GatewayVLESSPort == 0 && s.LegacyPublicEnabled == nil {
		return nil
	}
	if s.Role != RoleBridge || s.DevMode {
		return fmt.Errorf("managed public ingress requires production bridge")
	}
	if !s.LegacyPublicIsEnabled() && !s.PrimaryXHTTPIsPublished() {
		return fmt.Errorf("disabling legacy listeners requires primary XHTTP")
	}
	if s.ExperimentalProfileFile != "" && (!filepath.IsAbs(s.ExperimentalProfileFile) || s.GatewayVLESSPort == 0) {
		return fmt.Errorf("experimental profile requires absolute path and gateway listener")
	}
	ports := map[int]bool{HealthProbePort: true}
	_, ap, _ := net.SplitHostPort(s.AdminListen)
	if ap == "" {
		ap = "8443"
	}
	if s.Stats != nil {
		_, sp, _ := net.SplitHostPort(s.Stats.APIListen)
		if sp == "" {
			sp = "10085"
		}
		ap = ap + "," + sp
	}
	check := func(p int) error {
		if p < 1 || p > 65535 || ports[p] || strings.Contains(","+ap+",", fmt.Sprintf(",%d,", p)) || p == s.VLESSPort ||
			(s.PublicXHTTPTLS != nil && p == s.PublicXHTTPTLS.Port) ||
			(s.AntiCensor != nil && p == s.AntiCensor.PublicXHTTPPort) ||
			(s.BotTelegramProxy != nil && p == botTelegramProxyPort(s.BotTelegramProxy)) {
			return fmt.Errorf("ingress backend port conflict")
		}
		ports[p] = true
		return nil
	}
	if p := s.PrimaryXHTTP; p != nil {
		if err := validatePublicEndpoint(p.Host, &p.PublicXHTTPTLSSpec); err != nil {
			return err
		}
		if p.CertificateFile != "" || p.KeyFile != "" || p.Download != nil || p.BackendPort == p.Port {
			return fmt.Errorf("primary ingress TLS belongs to reverse proxy")
		}
		if err := check(p.BackendPort); err != nil {
			return err
		}
	}
	if s.GatewayVLESSPort > 0 {
		return check(s.GatewayVLESSPort)
	}
	return nil
}

func LoadExperimentalProfile(path string) (*ExperimentalProfile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16384 {
		return nil, fmt.Errorf("invalid experimental profile file")
	}
	var p ExperimentalProfile
	d := json.NewDecoder(io.LimitReader(f, 16385))
	d.DisallowUnknownFields()
	if err = d.Decode(&p); err != nil {
		return nil, fmt.Errorf("invalid experimental profile")
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("invalid experimental profile suffix")
	}
	if err = validatePublicEndpoint(p.Host, &p.Endpoint); err != nil {
		return nil, err
	}
	if p.Endpoint.CertificateFile != "" || p.Endpoint.KeyFile != "" || p.Endpoint.Download != nil || p.StatusPort < 1 ||
		p.StatusPort > 65535 {
		return nil, fmt.Errorf("experimental descriptor contains private or invalid fields")
	}
	return &p, nil
}

func BuildExperimentalExport(s *Spec, u auth.User, p *ExperimentalProfile) *ClientExport {
	return buildXHTTPTLSExport(s, u, p.Host, &p.Endpoint)
}

func (s *ExperimentalTransportSpec) Validate() error {
	if err := validatePublicEndpoint(s.Profile.Host, &s.Profile.Endpoint); err != nil {
		return err
	}
	t := &s.Profile.Endpoint
	if !filepath.IsAbs(t.CertificateFile) || !filepath.IsAbs(t.KeyFile) || s.BackendPort < 1 || s.BackendPort > 65535 ||
		s.Profile.StatusPort < 1 ||
		s.Profile.StatusPort > 65535 ||
		s.BackendPort == t.Port ||
		s.Profile.StatusPort == t.Port ||
		s.Profile.StatusPort == s.BackendPort ||
		t.Download != nil {
		return fmt.Errorf("invalid experimental gateway configuration")
	}
	return nil
}

func BuildExperimentalGateway(s *ExperimentalTransportSpec) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	spec := &Spec{PublicXHTTPTLS: &s.Profile.Endpoint}
	return json.Marshal(map[string]any{
		"log": map[string]any{"loglevel": "error"},
		"inbounds": []any{map[string]any{"listen": "0.0.0.0", "port": s.Profile.Endpoint.Port, "protocol": "dokodemo-door",
			"settings": map[string]any{
				"address": "127.0.0.1",
				"port":    s.BackendPort,
				"network": "tcp",
			}, "streamSettings": publicTLSStream(spec, true)}},
		"outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"proxyProtocol": 2}}},
	})
}
