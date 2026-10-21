package main

import (
	"errors"
	"strings"

	recoveryassets "github.com/NikitaDmitryuk/ultra/deploy/recovery"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// Credentials remain in private tagged variables, never process arguments.
func prepareAnsibleDNS(p *installplan.InstallPlan, variables map[string]any) error {
	if p.Automation == nil || p.Automation.DNS == nil {
		return nil
	}
	if p.Automation.Ingress == nil || p.Automation.Ingress.ForwardHost != "" {
		return errors.New("managed DNS requires direct bridge ingress")
	}
	secrets, err := installplan.ReadPlanSecrets(p)
	if err != nil {
		return err
	}
	key := strings.TrimSpace(secrets["ULTRA_VULTR_API_KEY"])
	if key == "" {
		return errors.New("canonical Vultr API key required for managed DNS")
	}
	source, err := recoveryassets.Scripts.ReadFile("dns.py")
	if err != nil {
		return err
	}
	policy := *p.Automation.DNS
	policy.APIKeyFile = "/etc/ultra-recovery/dns-api-key"
	variables["ultra_dns_source_content"] = string(source)
	variables["ultra_dns_api_key"] = key
	variables["ultra_dns_config"] = policy
	variables["ultra_dns_desired"] = map[string]any{
		"subscription": map[string]string{"name": policy.SubscriptionName, "data": p.Automation.BridgeIPv4},
		"vpn":          map[string]string{"name": policy.VPNName, "data": p.Automation.BridgeIPv4},
	}
	if p.Features.MainExitDomain != "" {
		variables["ultra_dns_desired"].(map[string]any)["tunnel"] = map[string]string{
			"name": strings.TrimSuffix(p.Features.MainExitDomain, "."+policy.Zone),
			"data": p.Exits[0].DialAddr,
		}
	}
	return nil
}
