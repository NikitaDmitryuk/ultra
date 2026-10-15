package installplan

import (
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

func validateAutomation(p *InstallPlan) error {
	if !p.FullAutomation() {
		return nil
	}
	if !p.Bridge.ReuseSpec && (!p.Bot.Enabled || !p.Database.Enabled) {
		return errors.New("clean v2 installation requires bot and database")
	}
	a := p.Automation
	if a == nil {
		return errors.New("schema 2 requires automation configuration; use apply --config with complete deployment policy")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`).MatchString(a.Version) || a.Version == "latest" {
		return errors.New("automation.version must identify an explicit immutable release")
	}
	if !filepath.IsAbs(a.ReleaseDir) || !filepath.IsAbs(a.KnownHostsFile) {
		return errors.New("automation release_dir and known_hosts_file must be absolute")
	}
	if a.CloudKeyFile != "" && !filepath.IsAbs(a.CloudKeyFile) {
		return errors.New("automation.cloud_key_file must be absolute")
	}
	if !strings.HasPrefix(a.AgeRecipient, "age1") || strings.ContainsAny(a.AgeRecipient, " \n\r\t") {
		return errors.New("automation.age_recipient must be a public age recipient")
	}
	if a.BridgeProvider == "" || net.ParseIP(a.BridgeIPv4).To4() == nil {
		return errors.New("automation requires bridge_provider and bridge_ipv4")
	}
	u, err := url.Parse(a.BridgeURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return errors.New("automation.bridge_url must be public HTTPS without credentials")
	}
	if len(a.StaticNodes) == 0 {
		return errors.New("automation requires initial static nodes with provider metadata")
	}
	fallbacks := 0
	addresses := map[string]bool{}
	for _, n := range a.StaticNodes {
		if net.ParseIP(n.Address) == nil || n.Name == "" || n.Provider == "" {
			return errors.New("automation static nodes require name, IP and provider")
		}
		address := net.ParseIP(n.Address).String()
		if addresses[address] {
			return errors.New("automation static node addresses must be unique")
		}
		addresses[address] = true
		if n.Budget == nil {
			if !p.Bridge.ReuseSpec {
				return errors.New("clean static exits require explicit traffic budgets")
			}
		} else {
			if n.Budget.MonthlyBytes <= 0 {
				return errors.New("static monthly_bytes must be positive")
			}
			if n.Budget.IsFallback {
				fallbacks++
			}
		}
	}
	if fallbacks > 1 {
		return errors.New("only one static fallback budget is allowed")
	}
	for _, path := range append(append([]string{}, a.StatePaths...), a.ArtifactPaths...) {
		if !filepath.IsAbs(path) || filepath.Clean(path) == "/" {
			return errors.New("automation backup paths must be explicit absolute paths")
		}
	}
	if a.ReadinessTimeoutSec == 0 {
		a.ReadinessTimeoutSec = 900
	}
	if a.ReadinessTimeoutSec < 30 || a.ReadinessTimeoutSec > 3600 {
		return errors.New("automation readiness timeout must be 30..3600 seconds")
	}

	if a.Ingress != nil {
		i := a.Ingress
		if i.Domain == "" {
			i.Domain = p.Bot.Domain
			if i.Domain == "" {
				i.Domain = p.Bridge.BotDomain
			}
		}
		if i.PublicHost == "" {
			i.PublicHost = a.BridgeIPv4
		}
		if !regexp.MustCompile(`^[a-z0-9][a-z0-9.-]+$`).MatchString(i.Domain) || strings.Contains(i.Domain, "..") || !strings.Contains(i.Email, "@") || !regexp.MustCompile(`^/[A-Za-z0-9_-]+$`).MatchString(i.Path) {
			return errors.New("automation ingress requires valid domain, ACME email and path")
		}
		if i.ForwardHost != "" && net.ParseIP(i.ForwardHost) == nil {
			return errors.New("ingress forward_host must be pinned node IP")
		}
		ports := []*int{&i.BackendPort, &i.GatewayPort, &i.StatusPort, &i.ExperimentalPort, &i.StagingPort}
		defaults := []int{18080, 18081, 18082, 5543, 18443}
		seen := map[int]bool{}
		for n, port := range ports {
			if *port == 0 {
				*port = defaults[n]
			}
			if *port < 1024 || *port > 65535 || seen[*port] {
				return errors.New("ingress ports must be distinct unprivileged ports")
			}
			seen[*port] = true
		}
	} else if !p.Bridge.ReuseSpec {
		return errors.New("clean v2 installation requires automation.ingress")
	}
	if a.DNS != nil {
		d := a.DNS
		label := regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
		validName := func(name string) bool {
			if len(name) > 253 || !strings.Contains(name, ".") {
				return false
			}
			for _, part := range strings.Split(name, ".") {
				if !label.MatchString(part) {
					return false
				}
			}
			return true
		}
		if d.Provider != "vultr" || !validName(d.Zone) || !label.MatchString(d.SubscriptionName) || !label.MatchString(d.VPNName) || d.SubscriptionName == d.VPNName {
			return errors.New("DNS requires vultr, a valid zone and distinct relative role labels")
		}
		if d.TTL == 0 {
			d.TTL = 300
		}
		// Ultra bounds operational TTLs; this is not a claim about provider API limits.
		if d.TTL < 120 || d.TTL > 86400 {
			return errors.New("DNS TTL must be 120..86400 seconds")
		}
		if a.Ingress == nil || p.PublicSubscriptionDomain() != d.SubscriptionName+"."+d.Zone || a.Ingress.Domain != d.VPNName+"."+d.Zone {
			return errors.New("DNS role names must match bot and VPN ingress domains")
		}
	}
	p.SSH.StrictHostKey = true
	return nil
}
