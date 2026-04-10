package config

// buildDNSSection returns the Xray "dns" configuration object for the given spec.
//
// Bridge role: Russian TLD domains (.ru, .su, .рф) and major Russian services on
// non-.ru domains (vk.com, yandex.com, …) are resolved via Yandex DoH running inside
// Russia — this produces correct IPs for direct connections.
// All other domains use Cloudflare 1.1.1.1 DoH.
//
// Exit role: All domains use Cloudflare 1.1.1.1 DoH, hiding DNS traffic from the exit ISP.
//
// Returns nil when AntiCensor.DisableDOH is true or spec.DevMode is true.
func buildDNSSection(spec *Spec) map[string]any {
	if spec.DevMode {
		return nil
	}
	if spec.AntiCensor != nil && spec.AntiCensor.DisableDOH {
		return nil
	}

	if spec.Role == RoleBridge {
		return buildBridgeDNS()
	}
	return buildExitDNS()
}

// buildBridgeDNS returns a DNS config routing Russian domains to Yandex DoH and
// everything else to Cloudflare DoH.
func buildBridgeDNS() map[string]any {
	// Domains that should be resolved via Yandex DoH (server is in Russia,
	// gives correct un-poisoned answers for Russian services).
	ruDomains := []string{
		// Russian ccTLDs
		"domain:ru",
		"domain:su",
		"domain:xn--p1ai", // IDN for .рф
		// Major Russian services that use non-Russian TLDs
		"domain:vk.com",
		"domain:vk.me",
		"domain:userapi.com", // VK CDN / API
		"domain:yandex.com",  // Yandex international entry
		"domain:yandex.net",  // Yandex internal CDN / infrastructure
		"domain:my.com",      // Mail.ru Group (international)
		"domain:sber.com",    // Sberbank international
	}
	return map[string]any{
		"servers": []any{
			// Yandex DoH: serves from inside Russia — correct answers for Russian domains.
			map[string]any{
				"address":      "https://common.dot.dns.yandex.net/dns-query",
				"domains":      ruDomains,
				"skipFallback": false,
			},
			// Cloudflare DoH: all other domains — prevents ISP from seeing international DNS.
			map[string]any{
				"address":      "https://1.1.1.1/dns-query",
				"skipFallback": false,
			},
			// System fallback in case DoH is unreachable.
			"localhost",
		},
	}
}

// buildExitDNS returns a DNS config routing all domains through Cloudflare DoH.
func buildExitDNS() map[string]any {
	return map[string]any{
		"servers": []any{
			// Cloudflare DoH — primary: private, fast, global.
			map[string]any{
				"address":      "https://1.1.1.1/dns-query",
				"skipFallback": false,
			},
			// Google DoH — secondary.
			map[string]any{
				"address":      "https://8.8.8.8/dns-query",
				"skipFallback": false,
			},
			// System fallback.
			"localhost",
		},
	}
}
