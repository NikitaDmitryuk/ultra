package mimic

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

func init() {
	Register("plusgaming", func() (Strategy, error) { return NewPlusGaming(), nil })
}

// PlusGaming is an HTTP template for the inter-node segment: host gw.cg.yandex.ru, REST-style
// paths and JSON-oriented headers consistent with a public web client talking to that API origin,
// with Origin/Referer pointing at plusgaming.yandex.ru. The outer TLS peer on the bridge is
// configured separately in spec (reality.*).
type PlusGaming struct{}

func NewPlusGaming() *PlusGaming { return &PlusGaming{} }

func (p *PlusGaming) Name() string { return "plusgaming" }

func (p *PlusGaming) Host() string { return "gw.cg.yandex.ru" }

func (p *PlusGaming) NextPath() string {
	// Path templates aligned with common GET JSON API routes on this host.
	templates := []string{
		"/api/v1/subscription",
		"/api/v1/session-intent",
		"/api/v1/billing/active-surge?streamerType=WEB",
		"/api/v1/subscription/games",
		"/api/v1/gamestore/accounts",
		"/api/v1/billing/payment-method",
	}
	var u [8]byte
	_, _ = rand.Read(u[:])
	w := binary.LittleEndian.Uint64(u[:])
	i := int(w % uint64(len(templates)))
	if w%3 == 0 {
		var g [2]byte
		_, _ = rand.Read(g[:])
		n := 1 + int(binary.BigEndian.Uint16(g[:])%180)
		return fmt.Sprintf("/api/v2/games/%d/state", n)
	}
	return templates[i]
}

func (p *PlusGaming) ExtraHeaders() map[string]string {
	return map[string]string{
		"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Accept":          "application/json",
		"Accept-Language": "ru,en;q=0.9",
		"Accept-Encoding": "gzip, deflate, br",
		"Origin":          "https://plusgaming.yandex.ru",
		"Referer":         "https://plusgaming.yandex.ru/",
		"Cache-Control":   "no-cache",
		"Pragma":          "no-cache",
		"Content-Type":    "application/json",
		"Sec-Fetch-Dest":  "empty",
		"Sec-Fetch-Mode":  "cors",
		"Sec-Fetch-Site":  "same-site",
	}
}
