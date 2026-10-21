package installplan

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// CanonicalValuesToPlan keeps deployment policy separate from secret file contents.
func CanonicalValuesToPlan(v map[string]string) (*InstallPlan, error) {
	p, err := canonicalRoleValuesToPlan(v)
	if err != nil {
		return nil, err
	}
	a := &AutomationConfig{
		Version:        v["ULTRA_AUTOMATION_VERSION"],
		ReleaseDir:     v["ULTRA_AUTOMATION_RELEASE_DIR"],
		AgeRecipient:   v["ULTRA_AUTOMATION_AGE_RECIPIENT"],
		BridgeProvider: v["ULTRA_AUTOMATION_BRIDGE_PROVIDER"],
		BridgeIPv4:     p.Bridge.Address,
		BridgeURL:      valueDefault(v, "ULTRA_AUTOMATION_BRIDGE_URL", "https://"+p.PublicSubscriptionDomain()+"/healthz"),
		KnownHostsFile: v["ULTRA_AUTOMATION_KNOWN_HOSTS_FILE"],
	}
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
		if p.Bridge.VLESSPort == 443 {
			return nil, errors.New("VLESS_PORT conflicts with the managed HTTPS ingress on port 443; choose another VLESS_PORT")
		}
		a.Ingress = &AutomationIngress{
			Domain:      domain,
			Email:       v["ACME_EMAIL"],
			Path:        v["PUBLIC_XHTTP_PATH"],
			ForwardHost: v["BOT_INGRESS_IP"],
			PublicHost:  valueDefault(v, "PUBLIC_HOST", a.BridgeIPv4),
		}
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
		a.DNS = &AutomationDNS{
			Provider:         provider,
			Zone:             v["DNS_ZONE"],
			TTL:              ttl,
			SubscriptionName: valueDefault(v, "DNS_SUBSCRIPTION_NAME", "sync"),
			VPNName:          valueDefault(v, "DNS_VPN_NAME", "edge"),
		}
	}
	if mode := v["SUBSCRIPTION_INGRESS_MODE"]; mode != "" {
		if mode != "direct" && mode != "forward" {
			return nil, errors.New("invalid SUBSCRIPTION_INGRESS_MODE")
		}
		if mode == "direct" && a.Ingress != nil {
			a.Ingress.ForwardHost = ""
		}
	}
	p.Automation = a
	return p, nil
}

// CanonicalLifecycleValuesToPlan projects an existing deployment's configuration.
// A bootstrap dump is never opened or carried into lifecycle plans or requests.
func CanonicalLifecycleValuesToPlan(v map[string]string) (*InstallPlan, error) {
	values := make(map[string]string, len(v))
	for key, value := range v {
		if key != "DATABASE_DUMP" && key != "DB_TUNNEL_PRIVATE_KEY_FILE" {
			values[key] = value
		}
	}
	p, err := CanonicalValuesToPlan(values)
	if err != nil {
		return nil, err
	}
	return LifecycleProjection(p), nil
}

// LifecycleProjection carries validation context across serialized lifecycle
// plans while dropping every bootstrap archive reference, including source data.
func LifecycleProjection(p *InstallPlan) *InstallPlan {
	projected := *p
	projected.LifecycleOnly = true
	projected.Secrets.DatabaseDumpFile = ""
	projected.Secrets.DatabaseDumpSHA256 = ""
	projected.Secrets.DatabaseTunnelPrivateKeyFile = ""
	projected.Secrets.DatabaseTunnelPrivateKeySHA256 = ""
	projected.SourceValues = make(map[string]string, len(p.SourceValues))
	for key, value := range p.SourceValues {
		if key != "DATABASE_DUMP" && key != "DB_TUNNEL_PRIVATE_KEY_FILE" {
			projected.SourceValues[key] = value
		}
	}
	return &projected
}

// AdoptionPreparationValuesToPlan reads only the role inputs for read-only
// adoption preparation. Its schema 2 envelope deliberately omits automation and
// cannot pass ValidatePlan; server-derived policy must produce a complete plan.
func AdoptionPreparationValuesToPlan(v map[string]string) (*InstallPlan, error) {
	p, err := canonicalRoleValuesToPlan(v)
	if err != nil {
		return nil, err
	}
	if !p.Bridge.ReuseSpec {
		return nil, errors.New("adoption preparation requires an existing bridge")
	}
	if err := validatePlanRoles(p); err != nil {
		return nil, err
	}
	return p, nil
}

func canonicalRoleValuesToPlan(v map[string]string) (*InstallPlan, error) {
	if err := validateCanonicalDeploymentKeys(v); err != nil {
		return nil, err
	}
	if version := valueDefault(v, "INSTALL_SCHEMA_VERSION", "2"); version != "2" {
		return nil, errors.New("only install schema 2 is supported")
	}
	p := LegacyValuesToPlan(v)
	if p.Secrets.DatabaseTunnelPrivateKeyFile != "" {
		if !p.Database.Enabled {
			return nil, errors.New("DB_TUNNEL_PRIVATE_KEY_FILE requires a dedicated database")
		}
		sum, err := DatabaseTunnelPrivateKeyDigest(p.Secrets.DatabaseTunnelPrivateKeyFile)
		if err != nil {
			return nil, err
		}
		p.Secrets.DatabaseTunnelPrivateKeySHA256 = sum
	}
	if p.Secrets.DatabaseDumpFile != "" {
		sum, err := DatabaseDumpDigest(p.Secrets.DatabaseDumpFile)
		if err != nil {
			return nil, err
		}
		p.Secrets.DatabaseDumpSHA256 = sum
	}
	p.SourceValues = make(map[string]string, len(v))
	for key, value := range v {
		p.SourceValues[key] = value
	}
	p.SchemaVersion = CurrentSchemaVersion
	p.Secrets.EnvFile = valueDefault(v, "SECRETS_ENV_FILE", p.SecretsEnvFile())
	return p, nil
}

func validateCanonicalDeploymentKeys(v map[string]string) error {
	for key := range v {
		switch key {
		case "PRESET":
			return errors.New("PRESET is removed; configure MAIN_EXIT_DOMAIN for the managed XHTTP TLS tunnel")
		case "BRIDGE",
			"EXIT",
			"DB_HOST",
			"IDENTITY",
			"FRONT",
			"BACK",
			"BRIDGE_SSH_HOST",
			"BRIDGE_SSH_IDENTITY",
			"EXIT_SSH_IDENTITY",
			"DB_SSH_IDENTITY",
			"DB_ENABLE",
			"DB_REPLICA",
			"DB_SSH_USER",
			"EXIT2",
			"EXIT2_SSH_IDENTITY",
			"EXIT2_NAME",
			"EXIT2_DIAL",
			"EXIT2_PRIORITY":
			return errors.New("removed deployment key " + key + "; use the canonical per-server IP and SSH_KEY fields")
		}
		if strings.HasPrefix(key, "ULTRA_AUTO_UPGRADE_") {
			return errors.New("automatic upgrade settings are no longer supported; use a manual release directory")
		}
		if DisallowedDeploymentSecret(key) {
			return errors.New("secret key " + key + " belongs outside install.config")
		}
	}
	return nil
}

// ReadSecretsFile does not merge process environment or execute shell expressions.
func ReadSecretsFile(path string) (map[string]string, error) { return parseLegacyEnvFile(path) }

// BotEnvironment projects only supported bot inputs; provider credentials never reach bot.env.
func BotEnvironment(values map[string]string) ([]byte, error) {
	if strings.TrimSpace(values["TELEGRAM_BOT_TOKEN"]) == "" {
		return nil, errors.New("TELEGRAM_BOT_TOKEN missing")
	}
	keys := []string{
		"TELEGRAM_BOT_TOKEN",
		"ULTRA_RELAY_ADMIN_TOKEN",
		"ULTRA_DB_DSN",
		"ULTRA_BOT_PUBLIC_URL",
		"ULTRA_BOT_TELEGRAM_SOCKS5",
		"ULTRA_XRAY_STATS_API",
	}
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

// DisallowedDeploymentSecret is shared by parsing and remote projection. API keys
// and private signing material belong in secrets, not deployment configuration.
func DisallowedDeploymentSecret(key string) bool {
	key = strings.ToUpper(key)
	if strings.HasSuffix(key, "_API_KEY") {
		return true
	}
	switch key {
	case "TELEGRAM_BOT_TOKEN",
		"ULTRA_CUTOVER_SUBSCRIPTION_URL",
		"ULTRA_SUBSCRIPTION_PROBE_URL",
		"ULTRA_RELAY_ADMIN_TOKEN",
		"ULTRA_DB_DSN":
		return true
	}
	signing := strings.Contains(key, "MINISIGN") || strings.Contains(key, "SIGNING")
	private := strings.Contains(key, "SECRET") || strings.Contains(key, "PRIVATE") || strings.Contains(key, "PASSWORD") ||
		strings.Contains(key, "PASSPHRASE")
	return signing && private
}
