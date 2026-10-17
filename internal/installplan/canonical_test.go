package installplan

import (
	"encoding/json"
	"strings"
	"testing"
)

func canonicalFixture() map[string]string {
	return map[string]string{
		"INSTALL_SCHEMA_VERSION": "2", "BRIDGE_IP": "192.0.2.1", "MAIN_EXIT_IP": "192.0.2.2", "BOT_DOMAIN": "sync.example.com", "VPN_DOMAIN": "edge.example.com", "VLESS_PORT": "24443", "ACME_EMAIL": "owner@example.com", "PUBLIC_XHTTP_PATH": "/connect", "DNS_PROVIDER": "vultr", "DNS_ZONE": "example.com", "ULTRA_AUTOMATION_VERSION": "v2.1", "ULTRA_AUTOMATION_RELEASE_DIR": "/release", "ULTRA_AUTOMATION_AGE_RECIPIENT": "age1fixture", "ULTRA_AUTOMATION_BRIDGE_PROVIDER": "a", "ULTRA_AUTOMATION_KNOWN_HOSTS_FILE": "/pins", "ULTRA_AUTOMATION_ADMIN_TELEGRAM_ID": "123", "ULTRA_AUTOMATION_STATIC_NODES": `[{"name":"NL","address":"192.0.2.2","provider":"a"}]`,
	}
}
func TestCanonicalV2MappingAndLegacyBoundary(t *testing.T) {
	v := canonicalFixture()
	p, err := CanonicalValuesToPlan(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAutomation(p); err != nil {
		t.Fatal(err)
	}
	if p.SchemaVersion != 2 || p.SecretsEnvFile() != ".env" || p.Automation.DNS.TTL != 300 ||
		p.Automation.Ingress.Domain != "edge.example.com" {
		t.Fatal("mapping lost policy")
	}
	delete(v, "INSTALL_SCHEMA_VERSION")
	p, err = CanonicalValuesToPlan(v)
	if err != nil || !p.FullAutomation() || p.SchemaVersion != CurrentSchemaVersion {
		t.Fatal("omitted version must default to schema 2")
	}
	v["INSTALL_SCHEMA_VERSION"] = "1"
	if _, err := CanonicalValuesToPlan(v); err == nil {
		t.Fatal("retired schema 1 accepted")
	}
	for _, key := range []string{"ULTRA_VULTR_API_KEY", "PROVIDER_API_KEY", "ULTRA_SUBSCRIPTION_PROBE_URL", "TELEGRAM_BOT_TOKEN"} {
		v := canonicalFixture()
		v[key] = "private-fixture"
		_, err := CanonicalValuesToPlan(v)
		if err == nil || strings.Contains(err.Error(), "private-fixture") {
			t.Fatal("secret config not safely rejected")
		}
	}
	v = canonicalFixture()
	v["ULTRA_AUTOMATION_STATIC_NODES"] = "bad-private-input"
	_, err = CanonicalValuesToPlan(v)
	if err == nil || strings.Contains(err.Error(), "bad-private") {
		t.Fatal("unsafe parsing")
	}
}

func TestCanonicalRejectsRemovedAutomaticUpgradePolicy(t *testing.T) {
	v := canonicalFixture()
	v["ULTRA_AUTO_UPGRADE_REPOSITORY"] = "example/project"
	if _, err := CanonicalValuesToPlan(v); err == nil {
		t.Fatal("removed automatic upgrade policy was silently ignored")
	}
}

func TestCanonicalRetiredRoleInputsAreRejected(t *testing.T) {
	for _, key := range []string{"PRESET", "BRIDGE", "EXIT", "DB_HOST", "IDENTITY", "BRIDGE_SSH_HOST", "BRIDGE_SSH_IDENTITY", "EXIT_SSH_IDENTITY", "DB_SSH_IDENTITY", "EXIT2", "DB_ENABLE", "DB_REPLICA", "DB_SSH_USER"} {
		v := canonicalFixture()
		v[key] = "retired"
		if _, err := CanonicalValuesToPlan(v); err == nil {
			t.Fatalf("retired key %s accepted", key)
		}
	}
}

func TestDNSRoleValidation(t *testing.T) {
	for _, value := range []string{"../vpn", "edge.example.com", "-vpn", "vpn_", ""} {
		p, _ := CanonicalValuesToPlan(canonicalFixture())
		p.Automation.DNS.VPNName = value
		if validateAutomation(p) == nil {
			t.Fatalf("accepted label %q", value)
		}
	}
	p, _ := CanonicalValuesToPlan(canonicalFixture())
	p.Automation.DNS.TTL = 119
	if validateAutomation(p) == nil {
		t.Fatal("accepted TTL")
	}
	p, _ = CanonicalValuesToPlan(canonicalFixture())
	p.Bot.Domain = "old.example.com"
	if validateAutomation(p) == nil {
		t.Fatal("accepted inconsistent domain")
	}
	raw, _ := json.Marshal(p)
	if strings.Contains(string(raw), "API_KEY") {
		t.Fatal("secret in plan")
	}
}
func TestBotEnvironmentExcludesProvidersAndUnknownKeys(t *testing.T) {
	out, err := BotEnvironment(
		map[string]string{
			"TELEGRAM_BOT_TOKEN":           "fixture",
			"ULTRA_VULTR_API_KEY":          "privatecompute",
			"ULTRA_SUBSCRIPTION_PROBE_URL": "https://sync.example.com/sub/privateprobe",
			"ARBITRARY":                    "privateother",
			"ULTRA_BOT_PUBLIC_URL":         "https://sync.example.com",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "private") || strings.Contains(string(out), "ULTRA_SUBSCRIPTION_PROBE_URL") ||
		!strings.Contains(string(out), "TELEGRAM_BOT_TOKEN=\"fixture\"") {
		t.Fatal("projection leaked or lost bot input")
	}
}

func TestSubscriptionProbeURLsAreDisallowedDeploymentSecrets(t *testing.T) {
	for _, key := range []string{"ULTRA_SUBSCRIPTION_PROBE_URL", "ULTRA_CUTOVER_SUBSCRIPTION_URL"} {
		if !DisallowedDeploymentSecret(key) {
			t.Fatalf("subscription probe URL key %q is not protected by shared deployment-secret rule", key)
		}
	}
}

func TestAnyAPIKeyIsDisallowedDeploymentSecret(t *testing.T) {
	for _, key := range []string{"ULTRA_VULTR_API_KEY", "EXAMPLE_PROVIDER_API_KEY", "example_provider_api_key"} {
		if !DisallowedDeploymentSecret(key) {
			t.Fatalf("API key name %q is allowed in deployment configuration", key)
		}
	}
}

func TestSeparateSubscriptionDomainPreservesBackendTLS(t *testing.T) {
	v := canonicalFixture()
	v["BOT_DOMAIN"] = "old.example.com"
	v["SUBSCRIPTION_DOMAIN"] = "sync.example.com"
	v["BOT_INGRESS_IP"] = "192.0.2.2"
	v["SUBSCRIPTION_INGRESS_MODE"] = "direct"
	p, err := CanonicalValuesToPlan(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAutomation(p); err != nil {
		t.Fatal(err)
	}
	if p.Bot.Domain != "old.example.com" || p.PublicSubscriptionDomain() != "sync.example.com" || p.Automation.Ingress.ForwardHost != "" {
		t.Fatal("backend TLS and public ingress conflated")
	}
	if p.Automation.BridgeURL != "https://sync.example.com/healthz" {
		t.Fatal("monitor URL is not public subscription host")
	}
}

func TestCanonicalExplicitBackupInventory(t *testing.T) {
	for _, key := range []string{"ULTRA_AUTOMATION_STATE_PATHS", "ULTRA_AUTOMATION_ARTIFACT_PATHS"} {
		for _, raw := range []string{"", "  ", "[]", `["/etc/owned/config", "/opt/owned/tool.py"]`} {
			v := canonicalFixture()
			v[key] = raw
			p, err := CanonicalValuesToPlan(v)
			if err != nil {
				t.Fatal(err)
			}
			paths := p.Automation.StatePaths
			if key == "ULTRA_AUTOMATION_ARTIFACT_PATHS" {
				paths = p.Automation.ArtifactPaths
			}
			if strings.Contains(raw, "/etc/") {
				if len(paths) != 2 || paths[0] != "/etc/owned/config" || paths[1] != "/opt/owned/tool.py" {
					t.Fatal("explicit inventory lost")
				}
			} else if len(paths) != 0 {
				t.Fatal("empty inventory expanded implicitly")
			}
		}
		for _, raw := range []string{"null", `{"path":"private-fixture"}`, `"private-fixture"`, `[1]`, `[null]`, `[""]`, "invalid-private-fixture"} {
			v := canonicalFixture()
			v[key] = raw
			if _, err := CanonicalValuesToPlan(v); err == nil || strings.Contains(err.Error(), "private-fixture") {
				t.Fatalf("invalid inventory not safely rejected for %s", key)
			}
		}
		v := canonicalFixture()
		v[key] = `["relative/path"]`
		p, err := CanonicalValuesToPlan(v)
		if err != nil {
			t.Fatal(err)
		}
		if validateAutomation(p) == nil {
			t.Fatal("relative backup path accepted")
		}
	}
	p, err := CanonicalValuesToPlan(canonicalFixture())
	if err != nil || len(p.Automation.StatePaths) != 0 || len(p.Automation.ArtifactPaths) != 0 {
		t.Fatal("omitted inventory changed defaults")
	}
}

func TestCanonicalRejectsPrivateSigningMaterialButAllowsPublicPolicy(t *testing.T) {
	for _, key := range []string{"MINISIGN_SECRET_KEY", "MINISIGN_PASSWORD", "MINISIGN_PRIVATE_KEY_FILE", "ULTRA_RELEASE_SIGNING_PRIVATE_KEY", "RELEASE_SIGNING_PASSPHRASE"} {
		values := canonicalFixture()
		values[key] = "sensitive-fixture"
		if _, err := CanonicalValuesToPlan(values); err == nil || strings.Contains(err.Error(), "sensitive-fixture") {
			t.Fatalf("private signing input not safely rejected: %s", key)
		}
	}
	if DisallowedDeploymentSecret("ULTRA_AUTO_UPGRADE_MINISIGN_PUBLIC_KEY_FILE") {
		t.Fatal("public verifier rejected")
	}
	values := canonicalFixture()
	values["ULTRA_RELEASE_MINISIGN_PUBLIC_KEY"] = "RWQtrusted-public-key"
	plan, err := CanonicalValuesToPlan(values)
	if err != nil || plan.SourceValues["ULTRA_RELEASE_MINISIGN_PUBLIC_KEY"] != "RWQtrusted-public-key" {
		t.Fatal("trusted public key was not kept in local source values")
	}
	encoded, err := json.Marshal(plan)
	if err != nil || strings.Contains(string(encoded), "RWQtrusted-public-key") {
		t.Fatal("trusted public key leaked into serialized install plan")
	}
}

func TestCanonicalIngressPorts(t *testing.T) {
	values := canonicalFixture()
	values["ULTRA_INGRESS_BACKEND_PORT"] = "19080"
	values["ULTRA_INGRESS_GATEWAY_PORT"] = "19081"
	values["ULTRA_INGRESS_STATUS_PORT"] = "19082"
	values["ULTRA_INGRESS_EXPERIMENTAL_PORT"] = "6543"
	values["ULTRA_INGRESS_STAGING_PORT"] = "19443"
	p, err := CanonicalValuesToPlan(values)
	if err != nil || validateAutomation(p) != nil {
		t.Fatal("valid custom ports rejected")
	}
	if p.Automation.Ingress.BackendPort != 19080 || p.Automation.Ingress.StagingPort != 19443 {
		t.Fatal("ports lost")
	}
	values["ULTRA_INGRESS_BACKEND_PORT"] = "private-invalid"
	if _, err := CanonicalValuesToPlan(values); err == nil || strings.Contains(err.Error(), "private-invalid") {
		t.Fatal("invalid port not safely rejected")
	}
}

func TestCanonicalVPNIngressDoesNotShareHTTPSPortWithVLESS(t *testing.T) {
	values := canonicalFixture()
	values["VLESS_PORT"] = "443"
	if _, err := CanonicalValuesToPlan(values); err == nil || !strings.Contains(err.Error(), "managed HTTPS ingress on port 443") {
		t.Fatalf("VLESS and managed HTTPS ingress must not share port 443: %v", err)
	}
	values["VLESS_PORT"] = "24443"
	if _, err := CanonicalValuesToPlan(values); err != nil {
		t.Fatalf("separate VLESS and HTTPS ports should be accepted: %v", err)
	}
}

func TestAdoptionPreparationCannotAuthorizeDeployment(t *testing.T) {
	values := map[string]string{
		"BRIDGE_IP":        "192.0.2.1",
		"MAIN_EXIT_IP":     "192.0.2.2",
		"BRIDGE_SSH_KEY":   "/identity",
		"SECRETS_ENV_FILE": "/private/secrets.env",
	}
	p, err := AdoptionPreparationValuesToPlan(values)
	if err != nil {
		t.Fatal(err)
	}
	if p.SchemaVersion != CurrentSchemaVersion || p.Automation != nil || p.BridgeSSHIdentity() != "/identity" ||
		p.SecretsEnvFile() != "/private/secrets.env" {
		t.Fatal("preparation changed the schema or access inputs")
	}
	if err := ValidatePlan(p); err == nil || !strings.Contains(err.Error(), "schema 2 requires automation configuration") {
		t.Fatalf("incomplete preparation authorized deployment: %v", err)
	}
	if _, err := CanonicalValuesToPlan(values); err == nil {
		t.Fatal("ordinary config parsing accepted incomplete policy")
	}
	for _, edit := range []map[string]string{
		{"INSTALL_SCHEMA_VERSION": "1"},
		{"REUSE_BRIDGE_SPEC": "false"},
		{"MAIN_EXIT_IP": ""},
		{"TELEGRAM_BOT_TOKEN": "private-fixture"},
		{"PRESET": "steamlike"},
	} {
		candidate := make(map[string]string, len(values)+len(edit))
		for key, value := range values {
			candidate[key] = value
		}
		for key, value := range edit {
			candidate[key] = value
		}
		if _, err := AdoptionPreparationValuesToPlan(candidate); err == nil || strings.Contains(err.Error(), "private-fixture") {
			t.Fatalf("unsafe preparation input accepted or exposed: %v", err)
		}
	}
}
