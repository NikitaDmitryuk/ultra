package config

import (
	"errors"
	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"net"
	"path/filepath"
	"strconv"
)

func (s *Spec) validateRTC() error {
	if !s.RTCService.Enabled {
		return nil
	}
	if s.Role != RoleBridge || s.Database == nil || s.Stats == nil {
		return errors.New("rtc: service requires bridge database and stats")
	}
	c := s.RTCService
	if c.ContentFile == "" || c.Socket == "" || c.GatewayPort < 1024 || c.GatewayPort > 65535 {
		return errors.New("rtc: service configuration incomplete")
	}
	if !filepath.IsAbs(c.ContentFile) || !filepath.IsAbs(c.Socket) {
		return errors.New("rtc: private paths must be absolute")
	}
	used := map[int]bool{s.VLESSPort: true, 11800: true}
	for _, addr := range []string{s.AdminListen, statsAPIListen(s)} {
		_, port, e := net.SplitHostPort(addr)
		if e == nil {
			n, _ := strconv.Atoi(port)
			used[n] = true
		}
	}
	if p := s.BotTelegramProxy; p != nil {
		used[botTelegramProxyPort(p)] = true
	}
	if p := s.PublicXHTTPTLS; p != nil {
		used[p.Port] = true
	}
	if p := s.AntiCensor; p != nil {
		used[p.PublicXHTTPPort] = true
	}
	if p := s.bridgeSOCKS5(); p != nil {
		used[p.Port] = true
		start, end := p.PortRangeStart, p.PortRangeEnd
		if start == 0 && end == 0 {
			start, end = 10810, 10899
		}
		if c.GatewayPort >= start && c.GatewayPort <= end {
			return errors.New("rtc: gateway port overlaps user allocation range")
		}
	}
	if used[c.GatewayPort] {
		return errors.New("rtc: gateway port conflicts with bridge listener")
	}
	return nil
}

func rtcIngress(s *Spec, _ []auth.User, _ []any) ([]any, []any, error) {
	if e := s.validateRTC(); e != nil {
		return nil, nil, e
	}
	if !s.RTCService.Enabled {
		return nil, nil, nil
	}
	return nil, []any{map[string]any{"type": "field", "inboundTag": []string{"rtc-service"}, "ip": []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"}, "outboundTag": resolveXrayWire(s).OutboundBlockTag}}, nil
}
