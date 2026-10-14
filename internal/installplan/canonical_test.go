package installplan

import (
	"encoding/json"
	"strings"
	"testing"
)

func canonicalFixture() map[string]string {
	return map[string]string{
		"INSTALL_SCHEMA_VERSION": "2", "BRIDGE": "192.0.2.1", "EXIT": "192.0.2.2", "BOT_DOMAIN": "sync.example.com", "VPN_DOMAIN": "edge.example.com", "ACME_EMAIL": "owner@example.com", "PUBLIC_XHTTP_PATH": "/connect", "DNS_PROVIDER": "vultr", "DNS_ZONE": "example.com", "ULTRA_AUTOMATION_VERSION": "v2.1", "ULTRA_AUTOMATION_RELEASE_DIR": "/release", "ULTRA_AUTOMATION_AGE_RECIPIENT": "age1fixture", "ULTRA_AUTOMATION_BRIDGE_PROVIDER": "a", "ULTRA_AUTOMATION_KNOWN_HOSTS_FILE": "/pins", "ULTRA_AUTOMATION_ADMIN_TELEGRAM_ID": "123", "ULTRA_AUTOMATION_STATIC_NODES": `[{"name":"NL","address":"192.0.2.2","provider":"a"}]`,
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
	if p.SchemaVersion != 2 || p.SecretsEnvFile() != ".env" || p.Automation.DNS.TTL != 300 || p.Automation.Ingress.Domain != "edge.example.com" {
		t.Fatal("mapping lost policy")
	}
	delete(v, "INSTALL_SCHEMA_VERSION")
	p, err = CanonicalValuesToPlan(v)
	if err != nil || p.FullAutomation() {
		t.Fatal("v1 acquired automation")
	}
	for _, key := range []string{"ULTRA_VULTR_API_KEY", "ULTRA_VULTR_DNS_API_KEY", "ULTRA_CUTOVER_SUBSCRIPTION_URL", "TELEGRAM_BOT_TOKEN"} {
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

func TestCanonicalV2BridgeSSHHostDoesNotChangeServiceAddress(t *testing.T) {
	v := canonicalFixture()
	v["BRIDGE_SSH_HOST"] = "bridge-admin"
	p, err := CanonicalValuesToPlan(v)
	if err != nil {
		t.Fatal(err)
	}
	if p.Bridge.Address != "192.0.2.1" || p.Bridge.SSHHost != "bridge-admin" {
		t.Fatalf("bridge address and SSH target were conflated: %#v", p.Bridge)
	}
	if p.Bridge.PublicHost != "192.0.2.1" {
		t.Fatalf("public host = %q, want service address", p.Bridge.PublicHost)
	}
	if p.Automation.BridgeIPv4 != "192.0.2.1" {
		t.Fatalf("automation bridge IPv4 = %q, want service address", p.Automation.BridgeIPv4)
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
	out, err := BotEnvironment(map[string]string{"TELEGRAM_BOT_TOKEN": "fixture", "ULTRA_VULTR_API_KEY": "privatecompute", "ULTRA_VULTR_DNS_API_KEY": "privatedns", "ARBITRARY": "privateother", "ULTRA_BOT_PUBLIC_URL": "https://sync.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "private") || !strings.Contains(string(out), "TELEGRAM_BOT_TOKEN=\"fixture\"") {
		t.Fatal("projection leaked or lost bot input")
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
