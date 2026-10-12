package config

import (
	"errors"
	"net/url"
	"strings"
)

// IsHappUserAgent recognises the Happ product token, not arbitrary substrings.
func IsHappUserAgent(ua string) bool {
	for _, token := range strings.Fields(ua) {
		if strings.EqualFold(strings.SplitN(token, "/", 2)[0], "happ") {
			return true
		}
	}
	return false
}

// ResolveSubscriptionFormat is shared by relay exports and offline bot delivery.
func ResolveSubscriptionFormat(format, transport, ua string, happDefault bool) (string, error) {
	if format != "" && format != "uri" && format != "happ" {
		return "", errors.New("unknown subscription format")
	}
	if transport != "" && transport != "xhttp-tls" {
		return "", errors.New("unsupported subscription transport")
	}
	if transport != "" {
		if format == "happ" {
			return "", errors.New("unsupported subscription transport or format")
		}
		return "uri", nil
	}
	if format != "" {
		return format, nil
	}
	if happDefault && IsHappUserAgent(ua) {
		return "happ", nil
	}
	return "uri", nil
}

// SubscriptionCacheQuery canonicalises the representation independently of UA.
func SubscriptionCacheQuery(format, transport string) string {
	q := url.Values{"format": {format}}
	if transport != "" {
		q.Set("transport", transport)
	}
	return q.Encode()
}
