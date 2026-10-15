package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"path/filepath"
	"strings"

	recoveryassets "github.com/NikitaDmitryuk/ultra/deploy/recovery"
	"github.com/NikitaDmitryuk/ultra/internal/config"
)

// domainCutoverDesired separates the public dial host from the TLS identity.
// Backend identity is observed by the caller, rather than inferred from desired config.
type domainCutoverDesired struct {
	Subscription, VPN, PublicHost, Zone, Email string
	BotDomain, BridgeIPv4                      string
	BotPort, StagingPort, StatusPort           int
	ExperimentalPort                           int
}

// buildDomainCutoverVariables does not inspect runtime, acquire locks, apply changes,
// or write canonical config. The caller owns lifecycle and evidence validation.
func buildDomainCutoverVariables(
	desired domainCutoverDesired,
	existing *config.Spec,
	directory, lockDirectory, subscriptionURL, dnsKey string,
	owned map[string]any,
) (map[string]any, error) {
	if existing == nil || !existing.PrimaryXHTTPIsPublished() || existing.PrimaryXHTTP.Port != 443 {
		return nil, errors.New("cutover requires existing published primary on port 443")
	}
	if !filepath.IsAbs(directory) || !filepath.IsAbs(lockDirectory) || desired.PublicHost == "" ||
		strings.ContainsAny(desired.PublicHost, "/:@?# \t\r\n\x00") {
		return nil, errors.New("cutover requires absolute transaction paths and a public dial host")
	}
	bridgeIP := net.ParseIP(desired.BridgeIPv4)
	if bridgeIP == nil || bridgeIP.To4() == nil || desired.BotPort < 1 || desired.BotPort > 65535 {
		return nil, errors.New("cutover requires bridge IPv4 and backend port")
	}
	if desired.Subscription == desired.VPN || subscriptionURL == "" || dnsKey == "" || owned == nil ||
		strings.ContainsAny(subscriptionURL+dnsKey, "\r\n\x00") {
		return nil, errors.New("cutover requires distinct domains and verified DNS and probe inputs")
	}
	if desired.StagingPort == 0 {
		desired.StagingPort = 18443
	}
	if desired.StatusPort == 0 {
		desired.StatusPort = 18082
	}
	if desired.ExperimentalPort == 0 {
		desired.ExperimentalPort = 5543
	}
	for _, domain := range []string{desired.Subscription, desired.VPN} {
		if desired.Zone == "" || !strings.HasSuffix(domain, "."+desired.Zone) {
			return nil, errors.New("cutover domains must belong to the owned zone")
		}
	}
	source, err := recoveryassets.Scripts.ReadFile("dns.py")
	if err != nil {
		return nil, err
	}
	contract, err := recoveryassets.Scripts.ReadFile("cutover_contract.py")
	if err != nil {
		return nil, err
	}
	gateway := existing.GatewayVLESSPort
	if gateway == 0 {
		gateway = 18081
	}
	params := map[string]any{
		"domain":              desired.VPN,
		"subscription_domain": desired.Subscription,
		"public_host":         desired.PublicHost,
		"path":                existing.PrimaryXHTTP.Path,
		"backend_port":        existing.PrimaryXHTTP.BackendPort,
		"gateway_port":        gateway,
		"staging_port":        desired.StagingPort,
		"status_port":         desired.StatusPort,
		"experimental_port":   desired.ExperimentalPort,
		"forward_host":        "",
		"email":               desired.Email,
	}
	txnHash := sha256.Sum256([]byte(directory))
	return map[string]any{
		"ultra_lock_directory": lockDirectory, "ultra_ingress_action": "cutover", "ultra_ingress": params, "ultra_ingress_transaction": "/var/lib/ultra-ingress/ansible-" + hex.EncodeToString(txnHash[:]),
		"ultra_ingress_email": desired.Email, "ultra_ingress_domains": uniqueIngressDomains(desired.Subscription, desired.VPN, desired.BotDomain), "ultra_subscription_enabled": true, "ultra_subscription_domain": desired.Subscription, "ultra_bot_domain": desired.BotDomain, "ultra_bot_port": desired.BotPort, "ultra_bridge_url": "https://" + desired.Subscription + "/healthz", "ultra_bridge_ipv4": bridgeIP.String(),
		"ultra_cutover_subscription_url": subscriptionURL, "ultra_cutover_contract_source": string(contract), "ultra_dns_source_content": string(source), "ultra_dns_api_key": dnsKey, "ultra_dns_receipt_seed": owned,
		"ultra_dns_config": map[string]any{
			"provider":          "vultr",
			"zone":              desired.Zone,
			"ttl":               300,
			"subscription_name": strings.TrimSuffix(desired.Subscription, "."+desired.Zone),
			"vpn_name":          strings.TrimSuffix(desired.VPN, "."+desired.Zone),
			"api_key_file":      "/etc/ultra-recovery/dns-api-key",
		},
		"ultra_dns_desired": map[string]any{
			"subscription": map[string]string{
				"name": strings.TrimSuffix(desired.Subscription, "."+desired.Zone),
				"data": bridgeIP.String(),
			},
			"vpn": map[string]string{"name": strings.TrimSuffix(desired.VPN, "."+desired.Zone), "data": bridgeIP.String()},
		},
	}, nil
}
