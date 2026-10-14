package installplan

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// CanonicalValuesToPlan keeps deployment policy separate from secret file contents.
func CanonicalValuesToPlan(v map[string]string) (*InstallPlan, error) {
	for key := range v {
		if DisallowedDeploymentSecret(key) {
			return nil, errors.New("secret key " + key + " belongs outside install.config")
		}
	}
	p := LegacyValuesToPlan(v)
	p.SourceValues = make(map[string]string, len(v))
	for key, value := range v {
		p.SourceValues[key] = value
	}
	version := valueDefault(v, "INSTALL_SCHEMA_VERSION", "1")
	if version == "1" {
		return p, nil
	}
	if version != "2" {
		return nil, errors.New("INSTALL_SCHEMA_VERSION must be 1 or 2")
	}
	p.SchemaVersion = 2
	p.Secrets.EnvFile = valueDefault(v, "SECRETS_ENV_FILE", p.SecretsEnvFile())
	a := &AutomationConfig{Version: v["ULTRA_AUTOMATION_VERSION"], ReleaseDir: v["ULTRA_AUTOMATION_RELEASE_DIR"], AgeRecipient: v["ULTRA_AUTOMATION_AGE_RECIPIENT"], BridgeProvider: v["ULTRA_AUTOMATION_BRIDGE_PROVIDER"], BridgeIPv4: valueDefault(v, "ULTRA_AUTOMATION_BRIDGE_IPV4", p.Bridge.Address), BridgeURL: valueDefault(v, "ULTRA_AUTOMATION_BRIDGE_URL", "https://"+p.PublicSubscriptionDomain()+"/healthz"), KnownHostsFile: v["ULTRA_AUTOMATION_KNOWN_HOSTS_FILE"]}
	if err := json.Unmarshal([]byte(v["ULTRA_AUTOMATION_STATIC_NODES"]), &a.StaticNodes); err != nil {
		return nil, errors.New("ULTRA_AUTOMATION_STATIC_NODES must be a JSON array of node policy")
	}
	for _, field := range []struct {
		key   string
		paths *[]string
	}{
		{"ULTRA_AUTOMATION_STATE_PATHS", &a.StatePaths},
		{"ULTRA_AUTOMATION_ARTIFACT_PATHS", &a.ArtifactPaths},
	} {
		if raw := strings.TrimSpace(v[field.key]); raw != "" {
			var paths []string
			if err := json.Unmarshal([]byte(raw), &paths); err != nil || paths == nil {
				return nil, errors.New(field.key + " must be a JSON array of path strings")
			}
			for _, path := range paths {
				if path == "" {
					return nil, errors.New(field.key + " must contain nonempty path strings")
				}
			}
			*field.paths = paths
		}
	}
	var err error
	a.AdminTelegramID, err = strconv.ParseInt(v["ULTRA_AUTOMATION_ADMIN_TELEGRAM_ID"], 10, 64)
	if err != nil {
		return nil, errors.New("ULTRA_AUTOMATION_ADMIN_TELEGRAM_ID must be an integer")
	}
	if raw := v["ULTRA_AUTOMATION_READINESS_TIMEOUT_SEC"]; raw != "" {
		a.ReadinessTimeoutSec, err = strconv.Atoi(raw)
		if err != nil {
			return nil, errors.New("invalid automation readiness timeout")
		}
	}
	if domain := v["VPN_DOMAIN"]; domain != "" {
		a.Ingress = &AutomationIngress{Domain: domain, Email: v["ACME_EMAIL"], Path: v["PUBLIC_XHTTP_PATH"], ForwardHost: v["BOT_INGRESS_IP"], PublicHost: valueDefault(v, "PUBLIC_HOST", a.BridgeIPv4)}
	}
	if a.Ingress != nil {
		for _, field := range []struct {
			key  string
			port *int
		}{
			{"ULTRA_INGRESS_BACKEND_PORT", &a.Ingress.BackendPort},
			{"ULTRA_INGRESS_GATEWAY_PORT", &a.Ingress.GatewayPort},
			{"ULTRA_INGRESS_STATUS_PORT", &a.Ingress.StatusPort},
			{"ULTRA_INGRESS_EXPERIMENTAL_PORT", &a.Ingress.ExperimentalPort},
			{"ULTRA_INGRESS_STAGING_PORT", &a.Ingress.StagingPort},
		} {
			if raw := v[field.key]; raw != "" {
				*field.port, err = strconv.Atoi(raw)
				if err != nil {
					return nil, errors.New("invalid " + field.key)
				}
			}
		}
	}
	if provider := v["DNS_PROVIDER"]; provider != "" {
		ttl, err := strconv.Atoi(valueDefault(v, "DNS_TTL", "300"))
		if err != nil {
			return nil, errors.New("invalid DNS_TTL")
		}
		a.DNS = &AutomationDNS{Provider: provider, Zone: v["DNS_ZONE"], TTL: ttl, SubscriptionName: valueDefault(v, "DNS_SUBSCRIPTION_NAME", "sync"), VPNName: valueDefault(v, "DNS_VPN_NAME", "edge")}
	}
	if mode := v["SUBSCRIPTION_INGRESS_MODE"]; mode != "" {
		if mode != "direct" && mode != "forward" {
			return nil, errors.New("invalid SUBSCRIPTION_INGRESS_MODE")
		}
		if mode == "direct" && a.Ingress != nil {
			a.Ingress.ForwardHost = ""
		}
	}
	if v["ULTRA_AUTO_UPGRADE_REPOSITORY"] != "" || v["ULTRA_AUTO_UPGRADE_MINISIGN_PUBLIC_KEY_FILE"] != "" || v["ULTRA_AUTO_UPGRADE_REQUIRED_CHECKS"] != "" {
		a.AutoUpgrade = &AutomationAutoUpgrade{Repository: v["ULTRA_AUTO_UPGRADE_REPOSITORY"], PublicKeyFile: v["ULTRA_AUTO_UPGRADE_MINISIGN_PUBLIC_KEY_FILE"]}
		if json.Unmarshal([]byte(v["ULTRA_AUTO_UPGRADE_REQUIRED_CHECKS"]), &a.AutoUpgrade.RequiredChecks) != nil {
			return nil, errors.New("ULTRA_AUTO_UPGRADE_REQUIRED_CHECKS must be a JSON array")
		}
	}
	p.Automation = a
	return p, nil
}

// ReadSecretsFile does not merge process environment or execute shell expressions.
func ReadSecretsFile(path string) (map[string]string, error) { return parseLegacyEnvFile(path) }

// BotEnvironment projects only supported bot inputs; provider credentials never reach bot.env.
func BotEnvironment(values map[string]string) ([]byte, error) {
	if strings.TrimSpace(values["TELEGRAM_BOT_TOKEN"]) == "" {
		return nil, errors.New("TELEGRAM_BOT_TOKEN missing")
	}
	keys := []string{"TELEGRAM_BOT_TOKEN", "ULTRA_RELAY_ADMIN_TOKEN", "ULTRA_DB_DSN", "ULTRA_BOT_PUBLIC_URL", "ULTRA_BOT_TELEGRAM_SOCKS5", "ULTRA_XRAY_STATS_API"}
	var out strings.Builder
	for _, key := range keys {
		if value, ok := values[key]; ok {
			if strings.ContainsAny(value, "\r\n\x00") {
				return nil, errors.New("invalid bot environment value")
			}
			// systemd EnvironmentFile accepts double quoted values with these escapes.
			value = strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(value)
			out.WriteString(key + "=\"" + value + "\"\n")
		}
	}
	return []byte(out.String()), nil
}

// DisallowedDeploymentSecret is shared by parsing and remote projection. Public
// verification key references are policy; private signing material is never deployable.
func DisallowedDeploymentSecret(key string) bool {
	key = strings.ToUpper(key)
	switch key {
	case "TELEGRAM_BOT_TOKEN", "ULTRA_VULTR_API_KEY", "ULTRA_VULTR_DNS_API_KEY", "ULTRA_CUTOVER_SUBSCRIPTION_URL", "ULTRA_RELAY_ADMIN_TOKEN", "ULTRA_DB_DSN":
		return true
	}
	signing := strings.Contains(key, "MINISIGN") || strings.Contains(key, "SIGNING")
	private := strings.Contains(key, "SECRET") || strings.Contains(key, "PRIVATE") || strings.Contains(key, "PASSWORD") || strings.Contains(key, "PASSPHRASE")
	return signing && private
}
