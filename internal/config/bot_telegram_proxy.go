package config

import (
	"net"
	"strconv"
)

const (
	// BotTelegramProxyInboundTag is the Xray inbound for ultra-bot → Telegram API via active exit.
	BotTelegramProxyInboundTag  = "bot-telegram-socks"
	botTelegramProxyDefaultPort = 10809
)

// BotTelegramProxySpec enables a local SOCKS5 inbound on the bridge for ultra-bot
// outbound Telegram API traffic, always routed to the active exit outbound.
type BotTelegramProxySpec struct {
	Enabled       bool   `json:"enabled"`
	ListenAddress string `json:"listen_address,omitempty"`
	Port          int    `json:"port"`
}

func (s *Spec) botTelegramProxy() *BotTelegramProxySpec {
	if s == nil || s.BotTelegramProxy == nil || !s.BotTelegramProxy.Enabled {
		return nil
	}
	return s.BotTelegramProxy
}

func botTelegramProxyListen(s *BotTelegramProxySpec) string {
	if s.ListenAddress != "" {
		return s.ListenAddress
	}
	return "127.0.0.1"
}

func botTelegramProxyPort(s *BotTelegramProxySpec) int {
	if s.Port <= 0 {
		return botTelegramProxyDefaultPort
	}
	return s.Port
}

// BotTelegramProxyAddr returns host:port for ULTRA_BOT_TELEGRAM_SOCKS5.
func (s *Spec) BotTelegramProxyAddr() string {
	p := s.botTelegramProxy()
	if p == nil {
		return ""
	}
	return net.JoinHostPort(botTelegramProxyListen(p), strconv.Itoa(botTelegramProxyPort(p)))
}
