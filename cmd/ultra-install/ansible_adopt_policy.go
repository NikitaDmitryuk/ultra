package main

import (
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// This opt-in imports an explicit endpoint, never an ambient SSH alias or its
// ProxyCommand. The inspection still requires the original identity and pins.
func adoptionSSHOverride(p *installplan.InstallPlan, host string) (*installplan.InstallPlan, error) {
	if p.Automation != nil || len(p.SourceValues) == 0 || net.ParseIP(host) == nil {
		return nil, errors.New("adoption_explicit_ssh_address_required")
	}
	values := make(map[string]string, len(p.SourceValues)+1)
	for key, value := range p.SourceValues {
		values[key] = value
	}
	values["BRIDGE_IP"] = host
	return installplan.CanonicalValuesToPlan(values)
}

// Recovery metadata supplies existing policy, never credentials or a second
// operator inventory. The caller obtained these fixed files using pinned SSH.
type adoptionPolicyError struct{ stage string }

func (*adoptionPolicyError) Error() string { return "adoption_policy_missing_or_conflicting" }

func prepareAdoptionConfig(p *installplan.InstallPlan, inspection bootstrapInspection, version, release, pins string) (*installplan.InstallPlan, []byte, error) {
	stage := "input"
	fail := func() (*installplan.InstallPlan, []byte, error) {
		return nil, nil, &adoptionPolicyError{stage: stage}
	}
	if p.Automation != nil || len(p.SourceValues) == 0 || !filepath.IsAbs(release) || !filepath.IsAbs(pins) {
		return fail()
	}
	var deployment struct {
		Version             string                         `json:"version"`
		BridgeIPv4          string                         `json:"bridge_ipv4"`
		BridgeProvider      string                         `json:"bridge_provider"`
		BridgeURL           string                         `json:"bridge_url"`
		Database            string                         `json:"database"`
		Ingress             *installplan.AutomationIngress `json:"ingress"`
		StaticNodes         []installplan.AutomationNode   `json:"static_nodes"`
		ControllerDirectory string                         `json:"controller_directory"`
		SubscriptionDomain  string                         `json:"subscription_domain"`
		IngressMode         string                         `json:"ingress_mode"`
	}
	var backup struct {
		Source        string   `json:"source"`
		Database      string   `json:"database"`
		Recipient     string   `json:"recipient"`
		StatePaths    []string `json:"state_paths"`
		ArtifactPaths []string `json:"artifact_paths"`
	}
	var reconcile struct {
		Database       string                       `json:"database"`
		BridgeProvider string                       `json:"bridge_provider"`
		BridgeURL      string                       `json:"bridge_url"`
		StaticNodes    []installplan.AutomationNode `json:"static_nodes"`
	}
	decode := func(name string, target any) bool {
		raw, err := inspection.file(name)
		return err == nil && len(raw) > 0 && validAdoptionMetadata(name, raw) && json.Unmarshal(raw, target) == nil
	}
	stage = "metadata"
	if !decode("deployment.json", &deployment) || !decode("backup.json", &backup) || !decode("reconcile.json", &reconcile) {
		return fail()
	}
	stage = "agreement"
	if deployment.Version == "" || deployment.BridgeProvider == "" || deployment.BridgeURL == "" || deployment.Database == "" || len(deployment.StaticNodes) == 0 || backup.Source != "bridge" || backup.Recipient == "" || deployment.BridgeProvider != reconcile.BridgeProvider || deployment.BridgeURL != reconcile.BridgeURL || deployment.Database != backup.Database || deployment.Database != reconcile.Database || deployment.Database != p.Database.Name || !reflect.DeepEqual(deployment.StaticNodes, reconcile.StaticNodes) {
		return fail()
	}
	stage = "bridge"
	address := net.ParseIP(deployment.BridgeIPv4)
	if address == nil || !address.Equal(net.ParseIP(p.Bridge.Address)) {
		return fail()
	}
	// Every canonical static endpoint must have exactly one policy entry and vice versa.
	stage = "nodes"
	addresses := map[string]bool{}
	for _, node := range deployment.StaticNodes {
		ip := net.ParseIP(node.Address)
		if ip == nil || addresses[ip.String()] {
			return fail()
		}
		addresses[ip.String()] = true
	}
	if len(addresses) != len(p.Exits) {
		return fail()
	}
	for _, exit := range p.Exits {
		ip := net.ParseIP(exit.DialAddr)
		if ip == nil || !addresses[ip.String()] {
			return fail()
		}
	}
	values := make(map[string]string, len(p.SourceValues)+25)
	for key, value := range p.SourceValues {
		values[key] = value
	}
	set := func(key, value string) bool {
		if prior := values[key]; prior != "" && prior != value {
			return false
		}
		values[key] = value
		return true
	}
	stage = "subscription"
	if deployment.IngressMode != "" {
		if (deployment.IngressMode != "direct" && deployment.IngressMode != "forward") || !set("SUBSCRIPTION_INGRESS_MODE", deployment.IngressMode) {
			return fail()
		}
		if deployment.IngressMode == "forward" && (deployment.Ingress == nil || strings.TrimSpace(deployment.Ingress.ForwardHost) == "") {
			return fail()
		}
	}
	if deployment.SubscriptionDomain != "" && !set("SUBSCRIPTION_DOMAIN", deployment.SubscriptionDomain) {
		return fail()
	}
	nodes, _ := json.Marshal(deployment.StaticNodes)
	for key, value := range map[string]string{
		"ULTRA_AUTOMATION_AGE_RECIPIENT": backup.Recipient, "ULTRA_AUTOMATION_BRIDGE_PROVIDER": deployment.BridgeProvider, "ULTRA_AUTOMATION_BRIDGE_URL": deployment.BridgeURL, "ULTRA_AUTOMATION_STATIC_NODES": string(nodes), "ULTRA_AUTOMATION_KNOWN_HOSTS_FILE": pins,
	} {
		stage = "managed_policy." + key
		if !set(key, value) {
			return fail()
		}
	}
	stage = "admin"
	raw, err := inspection.file("admin-chat-id")
	if err != nil {
		return fail()
	}
	admin := strings.TrimSpace(string(raw))
	if admin == "" {
		admin = values["ULTRA_AUTOMATION_ADMIN_TELEGRAM_ID"]
	}
	if _, err := strconv.ParseInt(admin, 10, 64); err != nil || !set("ULTRA_AUTOMATION_ADMIN_TELEGRAM_ID", admin) {
		return fail()
	}
	if ingress := deployment.Ingress; ingress != nil {
		for key, value := range map[string]string{"VPN_DOMAIN": ingress.Domain, "ACME_EMAIL": ingress.Email, "PUBLIC_XHTTP_PATH": ingress.Path, "PUBLIC_HOST": ingress.PublicHost, "BOT_INGRESS_IP": ingress.ForwardHost} {
			stage = "ingress." + key
			// Direct subscription mode already clears the effective ForwardHost in
			// the canonical parser. Keep an unused legacy backend address without
			// interpreting it as a request to restore the forwarding ingress.
			if key == "BOT_INGRESS_IP" && deployment.IngressMode == "direct" && value == "" {
				continue
			}
			if !set(key, value) {
				return fail()
			}
		}
		for key, value := range map[string]int{"ULTRA_INGRESS_BACKEND_PORT": ingress.BackendPort, "ULTRA_INGRESS_GATEWAY_PORT": ingress.GatewayPort, "ULTRA_INGRESS_STATUS_PORT": ingress.StatusPort, "ULTRA_INGRESS_EXPERIMENTAL_PORT": ingress.ExperimentalPort, "ULTRA_INGRESS_STAGING_PORT": ingress.StagingPort} {
			stage = "ingress." + key
			if value != 0 && !set(key, strconv.Itoa(value)) {
				return fail()
			}
		}
	}
	stage = "dns"
	dnsRaw, err := inspection.file("dns.json")
	if err != nil {
		return fail()
	}
	if len(dnsRaw) > 0 {
		var dns struct {
			Config installplan.AutomationDNS `json:"config"`
		}
		if !validAdoptionMetadata("dns.json", dnsRaw) || json.Unmarshal(dnsRaw, &dns) != nil || dns.Config.Provider == "" {
			return fail()
		}
		for key, value := range map[string]string{"DNS_PROVIDER": dns.Config.Provider, "DNS_ZONE": dns.Config.Zone, "DNS_TTL": strconv.Itoa(dns.Config.TTL), "DNS_SUBSCRIPTION_NAME": dns.Config.SubscriptionName, "DNS_VPN_NAME": dns.Config.VPNName} {
			stage = "dns." + key
			if !set(key, value) {
				return fail()
			}
		}
	} else if values["DNS_PROVIDER"] != "" {
		return fail()
	}
	// Only the controller tree explicitly identified by deployment metadata is
	// replaced by bootstrap. Unrelated or historical trees remain in coverage.
	stage = "controller"
	controller := deployment.ControllerDirectory
	if controller != "" && (!validAutomationVersion(deployment.Version) ||
		(controller != "/opt/ultra-ansible/releases/"+deployment.Version && controller != managedControllerDirectory(deployment.Version))) {
		return fail()
	}
	for key, paths := range map[string][]string{"ULTRA_AUTOMATION_STATE_PATHS": backup.StatePaths, "ULTRA_AUTOMATION_ARTIFACT_PATHS": backup.ArtifactPaths} {
		stage = "backup_paths." + key
		extras, err := adoptionBackupExtras(paths, controller)
		if err != nil {
			return fail()
		}
		if old := values[key]; old != "" {
			var declared []string
			if json.Unmarshal([]byte(old), &declared) != nil {
				return fail()
			}
			for _, path := range declared {
				found := false
				for _, retained := range paths {
					if retained == path {
						found = true
					}
				}
				if !found {
					return fail()
				}
			}
		}
		encoded, _ := json.Marshal(extras)
		values[key] = string(encoded)
	}
	values["REUSE_BRIDGE_SPEC"] = "true"
	values["ULTRA_AUTOMATION_VERSION"] = version
	values["ULTRA_AUTOMATION_RELEASE_DIR"] = release
	stage = "validation"
	candidate, err := installplan.CanonicalValuesToPlan(values)
	if err != nil || installplan.ValidatePlan(candidate) != nil {
		return fail()
	}
	stage = "render"
	rendered, err := renderCanonicalInputs(values)
	if err != nil {
		return fail()
	}
	return candidate, rendered, nil
}

// These owned baselines are generated by the former automation.py and current
// bootstrap_plan.py. Custom certificate, ingress and geo paths remain explicit;
// exact shipped recovery scripts/units and the declared controller are regenerated.
func adoptionBackupExtras(paths []string, regeneratedController ...string) ([]string, error) {
	owned := map[string]bool{}
	for _, path := range []string{"/etc/ultra-fleet", "/etc/ultra-relay", "/etc/ultra-recovery", "/var/lib/ultra-relay/automation", "/etc/systemd/system/ultra-relay.service", "/etc/systemd/system/ultra-relay.service.d", "/etc/systemd/system/ultra-bot.service", "/etc/systemd/system/ultra-auto-upgrade.service", "/etc/systemd/system/ultra-auto-upgrade.timer", "/var/lib/ultra-recovery-reconcile/heartbeat_ed25519", "/var/lib/ultra-recovery-reconcile/heartbeat_ed25519.pub", "/usr/local/bin/ultra-relay", "/usr/local/bin/ultra-bot", "/usr/local/bin/ultra-client", "/usr/local/bin/ultra-install", "/usr/local/libexec/ultra-relay-emergency", "/usr/local/libexec/ultra-emergency-manifest.json", "/usr/local/libexec/ultra-emergency-manifest.json.minisig", "/var/lib/ultra-ansible/channel", "/etc/ultra-ansible", "/etc/systemd/system/ultra-ansible-controller.service"} {
		owned[path] = true
	}
	// Keep this exact member list aligned with the non-test recovery archive in
	// Makefile. Directory, extension and prefix matches would erase custom hooks.
	for _, name := range []string{
		"bootstrap_plan.py", "db_connection.py", "cutover_contract.py", "dns.py", "domain_cutover.py", "heartbeat.py", "monitor.py",
		"operator_access.py", "reconcile.py", "recovery.py", "recovery_key.py", "recovery_status.py", "restore.py",
		"restore_ansible.py", "restore_database.py", "restore_firewall.py", "restore_common.py", "restore_host.py", "restore_peer.py", "smoke.py",
		"ultra-monitor-probe.service", "ultra-monitor.service", "ultra-monitor.timer",
		"ultra-recovery-backup.service", "ultra-recovery-backup.timer", "ultra-recovery-prune.service", "ultra-recovery-prune.timer",
		"ultra-recovery-reconcile.service", "ultra-recovery-reconcile.timer",
		"release-manifest.json", "release-manifest.json.minisig",
	} {
		owned["/opt/ultra-recovery/"+name] = true
		if strings.HasSuffix(name, ".service") || strings.HasSuffix(name, ".timer") {
			owned["/etc/systemd/system/"+name] = true
		}
	}
	for _, controller := range regeneratedController {
		if controller != "" {
			owned[controller] = true
		}
	}
	extras := []string{}
	seen := map[string]bool{}
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsAny(path, "\r\n\x00") {
			return nil, errors.New("adoption_backup_path_invalid")
		}
		if owned[path] {
			continue
		}
		if !seen[path] {
			extras = append(extras, path)
			seen[path] = true
		}
	}
	return extras, nil
}

// Unknown policy fields cannot silently disappear during a one-time conversion.
// Auxiliary fields are references emitted by the existing recovery planner.
func validAdoptionMetadata(name string, raw []byte) bool {
	fields := map[string]string{
		"deployment.json": "version bridge_ipv4 bridge_provider bridge_url database ingress static_nodes ssh_identity_file known_hosts_file controller_directory subscription_domain ingress_mode",
		"backup.json":     "source repository database recipient identity_file known_hosts destinations independent state_paths artifact_paths diagnostic_status",
		"reconcile.json":  "database bridge_provider vultr_state_dir ssh_identity_file vultr_api_key_file api_key_owner ssh_identity_owner backup_config state_dir status_file status_group bundle_dir client_binary installer_binary bot_token_file chat_id_file probe_profile_file bridge_url payload_url static_nodes monitor_spec_file",
		"dns.json":        "config desired",
	}
	var object map[string]json.RawMessage
	if !adoptionObjectFields(raw, fields[name], &object) {
		return false
	}
	if nodes, exists := object["static_nodes"]; exists {
		var entries []json.RawMessage
		if json.Unmarshal(nodes, &entries) != nil || len(entries) == 0 {
			return false
		}
		for _, entry := range entries {
			var node map[string]json.RawMessage
			if !adoptionObjectFields(entry, "name address provider budget id known_hosts", &node) {
				return false
			}
			if budget, exists := node["budget"]; exists && string(budget) != "null" {
				if !adoptionObjectFields(budget, "monthly_bytes is_fallback", nil) {
					return false
				}
			}
		}
	}
	if ingress, exists := object["ingress"]; exists && string(ingress) != "null" {
		if !adoptionObjectFields(ingress, "domain email path forward_host public_host backend_port gateway_port status_port experimental_port staging_port", nil) {
			return false
		}
	}
	if name == "dns.json" {
		if !adoptionObjectFields(object["config"], "provider zone ttl subscription_name vpn_name api_key_file", nil) {
			return false
		}
	}
	return true
}
func adoptionObjectFields(raw []byte, allowed string, output *map[string]json.RawMessage) bool {
	var object map[string]json.RawMessage
	if allowed == "" || json.Unmarshal(raw, &object) != nil || object == nil {
		return false
	}
	keys := map[string]bool{}
	for _, key := range strings.Fields(allowed) {
		keys[key] = true
	}
	for key := range object {
		if !keys[key] {
			return false
		}
	}
	if output != nil {
		*output = object
	}
	return true
}
