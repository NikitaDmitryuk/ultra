package mimic

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

func init() {
	Register("apijson", func() (Strategy, error) { return NewAPIJSON(), nil })
	// Legacy preset id from older specs; same behavior as apijson.
	Register("plusgaming", func() (Strategy, error) { return NewAPIJSON(), nil })
}

// DefaultSplithttpHost is the HTTP Host / TLS CN hint when spec.splithttp_host is unset.
// It uses the reserved ".invalid" TLD (RFC 6761); operators should set splithttp_host in production.
const DefaultSplithttpHost = "splithttp.invalid"

// APIJSON is an HTTP template for the inter-node splithttp segment: JSON API–like paths and
// browser-style headers. Public inbound TLS (REALITY) is configured separately in spec.reality.
type APIJSON struct{}

func NewAPIJSON() *APIJSON { return &APIJSON{} }

func (p *APIJSON) Name() string { return "apijson" }

func (p *APIJSON) Host() string { return DefaultSplithttpHost }

func (p *APIJSON) NextPath() string {
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

func (p *APIJSON) ExtraHeaders() map[string]string {
	base := "https://" + DefaultSplithttpHost
	return map[string]string{
		"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Accept":          "application/json",
		"Accept-Language": "en-US,en;q=0.9",
		"Accept-Encoding": "gzip, deflate, br",
		"Origin":          base,
		"Referer":         base + "/",
		"Cache-Control":   "no-cache",
		"Pragma":          "no-cache",
		"Content-Type":    "application/json",
		"Sec-Fetch-Dest":  "empty",
		"Sec-Fetch-Mode":  "cors",
		"Sec-Fetch-Site":  "same-site",
	}
}
