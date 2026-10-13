// Package subscriptionmeta keeps subscription metadata consistent across relay,
// proxy and autonomous cache responses.
package subscriptionmeta

import (
	"encoding/base64"
	"net/http"
	"time"
)

// Headers is the metadata allowlist for confirmed subscription responses.
var Headers = []string{
	"Content-Type", "profile-title", "profile-update-interval", "Vary",
	"subscription-userinfo", "support-url", "announce", "X-Ultra-Quota-Scope",
	"X-Ultra-Quota-Period", "X-Ultra-Quota-State", "X-Ultra-Quota-Observed-At",
	"X-Ultra-Quota-Resets-At",
}

func Announce(h http.Header, message string) {
	runes := []rune(message)
	if len(runes) > 200 {
		message = string(runes[:197]) + "…"
	}
	h.Set("announce", "base64:"+base64.StdEncoding.EncodeToString([]byte(message)))
}

// MarkStale leaves the confirmed quota and its reset time untouched. In
// particular, crossing a month boundary must not invent a renewed allowance.
func MarkStale(h http.Header, confirmed time.Time) {
	h.Set("X-Ultra-Quota-Freshness", "stale")
	h.Set("X-Ultra-Cache-Confirmed-At", confirmed.UTC().Format(time.RFC3339))
	message := "Автономный кеш: данные устарели; подтверждены " + confirmed.UTC().Format(time.RFC3339) + "."
	if raw := h.Get("announce"); len(raw) > len("base64:") && raw[:len("base64:")] == "base64:" {
		if decoded, err := base64.StdEncoding.DecodeString(raw[len("base64:"):]); err == nil {
			message += " " + string(decoded)
		}
	}
	Announce(h, message)
}
