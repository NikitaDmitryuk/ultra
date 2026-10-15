package config

import (
	"net/url"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
)

// Service rules precede ordinary split routing: monitor credentials cannot be
// repurposed for arbitrary destinations or direct egress.
func serviceRouting(users []auth.User, active, block string) []any {
	var rules []any
	for _, u := range users {
		if len(u.ServiceTargets) == 0 {
			continue
		}
		tag := active
		if u.EffectiveExitID == auth.BlockedExit {
			tag = block
		} else if u.EffectiveExitID != "" {
			tag = exits.OutboundTag(u.EffectiveExitID)
		}
		domains := []string{}
		for _, target := range u.ServiceTargets {
			parsed, e := url.Parse(target)
			if e == nil && parsed.Scheme == "https" && parsed.Hostname() != "" {
				domains = append(domains, "full:"+parsed.Hostname())
			}
		}
		if len(domains) > 0 {
			rules = append(
				rules,
				map[string]any{
					"type":        "field",
					"user":        []string{u.UUID},
					"domain":      domains,
					"network":     "tcp",
					"port":        "443",
					"outboundTag": tag,
				},
			)
		}
		rules = append(rules, map[string]any{"type": "field", "user": []string{u.UUID}, "outboundTag": block})
	}
	return rules
}
