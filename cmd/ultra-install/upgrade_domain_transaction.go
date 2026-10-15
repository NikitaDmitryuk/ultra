package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	recoveryassets "github.com/NikitaDmitryuk/ultra/deploy/recovery"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

type upgradeDomainProbeKey struct{}

// The private input is deliberately outside immutable requests. Those requests
// bind only its private path and exact digest, never the credential itself.
func withUpgradeDomainProbeFile(ctx context.Context, path string) context.Context {
	return context.WithValue(ctx, upgradeDomainProbeKey{}, path)
}

func readUpgradeDomainProbe(path, hostname string) (string, error) {
	value, _, err := readUpgradeDomainProbeInput(path, hostname)
	return value, err
}

func readUpgradeDomainProbeInput(path, hostname string) (string, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", "", errors.New("upgrade_domain_probe_private_file_required")
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", "", errors.New("upgrade_domain_probe_private_file_required")
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", "", errors.New("upgrade_domain_probe_private_file_required")
	}
	f := os.NewFile(uintptr(fd), "private-domain-probe")
	defer f.Close() //nolint:errcheck
	var info syscall.Stat_t
	if syscall.Fstat(fd, &info) != nil || info.Mode&syscall.S_IFMT != syscall.S_IFREG || info.Mode&0077 != 0 || info.Uid != uint32(os.Geteuid()) || info.Nlink != 1 || info.Size < 1 || info.Size > 4096 {
		return "", "", errors.New("upgrade_domain_probe_private_file_required")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return "", "", errors.New("upgrade_domain_probe_invalid")
	}
	value := strings.TrimSuffix(string(raw), "\n")
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host != hostname || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(u.Path, "/sub/") || len(strings.TrimPrefix(u.Path, "/sub/")) < 1 || strings.ContainsAny(value, " \t\r\n\x00") || !regexp.MustCompile(`^/sub/[A-Za-z0-9_-]+$`).MatchString(u.Path) || len(u.Path) > 1029 || u.RawPath != "" {
		return "", "", errors.New("upgrade_domain_probe_invalid")
	}
	return value, fmt.Sprintf("%x", sha256.Sum256(raw)), nil
}

type upgradeDomainEvidence struct {
	BridgeURL             string `json:"bridge_url"`
	BridgeIPv4            string `json:"bridge_ipv4"`
	Zone                  string `json:"zone"`
	DNSTTL                int    `json:"dns_ttl"`
	ACMEEmailMatches      bool   `json:"acme_email_matches"`
	IngressModeMatches    bool   `json:"ingress_mode_matches"`
	ForwardHostMatches    bool   `json:"forward_host_matches"`
	StagingPortMatches    bool   `json:"staging_port_matches"`
	StagingPortUnrecorded bool   `json:"staging_port_unrecorded"`
	StatusPortMatches     bool   `json:"status_port_matches"`
	ExperimentalPortMatch bool   `json:"experimental_port_matches"`
	AgeRecipientMatches   bool   `json:"age_recipient_matches"`
	BridgeProviderMatches bool   `json:"bridge_provider_matches"`
	StaticNodesMatch      bool   `json:"static_nodes_match"`
	AdminIDMatches        bool   `json:"admin_id_matches"`
	StatePathsMatch       bool   `json:"state_paths_match"`
	ArtifactPathsMatch    bool   `json:"artifact_paths_match"`
	Verified              bool   `json:"verified"`
	Subscription          string `json:"subscription"`
	Backend               string `json:"backend"`
	VPN                   string `json:"vpn"`
	PublicHost            string `json:"public_host"`
	Path                  string `json:"path"`
	BackendPort           int    `json:"backend_port"`
	BotPort               int    `json:"bot_port"`
	GatewayPort           int    `json:"gateway_port"`
	Fingerprint           string `json:"fingerprint"`
}

type upgradeDomainTransaction struct {
	Changed            bool
	DNSChanged         bool
	BackendChanged     bool
	BackupPathsChanged bool
	Evidence           upgradeDomainEvidence
	Variables          map[string]any
	Desired            map[string]any
	Binding            string
	ProbeFile          string
	ProbeSHA256        string
	Attempt            int
}

func inspectUpgradeDomains(ctx context.Context, p *installplan.InstallPlan, inventory, releaseVariables map[string]any, directory, python, executable string) (*upgradeDomainTransaction, error) {
	t := &upgradeDomainTransaction{}
	if err := validateUpgradeDomainConfigPresence(p); err != nil {
		return nil, err
	}
	if p.Automation == nil {
		return t, nil
	}
	ingress, dns := p.Automation.Ingress, p.Automation.DNS
	ingressMode := "direct"
	if ingress.ForwardHost != "" {
		ingressMode = "forward"
	}
	desired := map[string]any{"subscription": p.PublicSubscriptionDomain(), "vpn": ingress.Domain, "backend": p.Bot.Domain, "public_host": p.Bridge.PublicHost}
	policy := map[string]any{
		"email": ingress.Email, "ingress_mode": ingressMode, "forward_host": ingress.ForwardHost, "dns_ttl": dns.TTL,
		"backend_port": ingress.BackendPort, "gateway_port": ingress.GatewayPort, "staging_port": ingress.StagingPort,
		"status_port": ingress.StatusPort, "experimental_port": ingress.ExperimentalPort,
		"age_recipient": p.Automation.AgeRecipient, "bridge_provider": p.Automation.BridgeProvider,
		"static_nodes": p.Automation.StaticNodes, "admin_telegram_id": p.Automation.AdminTelegramID,
		"bridge_ipv4": p.Automation.BridgeIPv4, "state_paths": append([]string{}, p.Automation.StatePaths...),
		"artifact_paths": append([]string{}, p.Automation.ArtifactPaths...)}
	binding := sha256.Sum256([]byte(lifecycleID(directory)))
	t.Binding = hex.EncodeToString(binding[:])
	receipt, err := runUpgradeInspection(ctx, "inspect-upgrade-domains", inventory, map[string]any{"ultra_lock_directory": releaseVariables["ultra_lock_directory"], "ultra_upgrade_domain_transaction": t.Binding, "ultra_upgrade_domain_desired": desired, "ultra_upgrade_domain_policy": policy}, filepath.Join(directory, "domain-inspect"), python, executable)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(receipt.Result.Values)
	if err != nil || json.Unmarshal(raw, &t.Evidence) != nil || !t.Evidence.Verified {
		return nil, errors.New("upgrade_domain_evidence_invalid")
	}
	e := t.Evidence
	if err = validateUpgradeDomainPolicy(e, ingress, dns, p.Automation); err != nil {
		return nil, err
	}
	t.DNSChanged = e.Subscription != p.PublicSubscriptionDomain() || e.VPN != ingress.Domain || e.Backend != p.Bot.Domain || e.PublicHost != p.Bridge.PublicHost
	t.BackendChanged = e.Backend != p.Bot.Domain || e.BotPort != p.Bot.Port
	t.BackupPathsChanged = upgradeBackupPathsChanged(e)
	t.Changed = t.DNSChanged || e.Path != ingress.Path || t.BackendChanged || e.BridgeURL != p.Automation.BridgeURL || t.BackupPathsChanged
	if !t.Changed {
		return t, nil
	}
	if t.DNSChanged && e.Zone != dns.Zone {
		return nil, errors.New("upgrade_domain_dns_zone_migration_required")
	}
	ip := net.ParseIP(p.Automation.BridgeIPv4)
	if ip == nil || ip.To4() == nil || !p.Bot.Enabled || ingress.ForwardHost != "" {
		return nil, errors.New("upgrade_domain_managed_bridge_required")
	}
	if err := validateUpgradePublicHostChange(e.PublicHost, p.Bridge.PublicHost, ingress.Domain, ip.String()); err != nil {
		return nil, err
	}
	if t.DNSChanged {
		for _, name := range []string{p.PublicSubscriptionDomain(), ingress.Domain, p.Bot.Domain} {
			label := strings.TrimSuffix(name, "."+dns.Zone)
			if !strings.HasSuffix(name, "."+dns.Zone) || strings.Contains(label, ".") || label == "" {
				return nil, errors.New("upgrade_domain_owned_zone_required")
			}
		}
		if p.Bot.Domain == p.PublicSubscriptionDomain() || p.Bot.Domain == ingress.Domain {
			return nil, errors.New("upgrade_domain_distinct_backend_required")
		}
	}
	t.ProbeFile, _ = ctx.Value(upgradeDomainProbeKey{}).(string)
	if t.Changed {
		if _, t.ProbeSHA256, err = readUpgradeDomainProbeInput(t.ProbeFile, e.Subscription); err != nil {
			return nil, err
		}
		if err = writeUpgradeInput(filepath.Join(directory, "domain-probe.sha256"), []byte(t.ProbeSHA256)); err != nil {
			return nil, err
		}
	}
	source, err := recoveryassets.Scripts.ReadFile("cutover_contract.py")
	if err != nil {
		return nil, err
	}
	t.Desired = map[string]any{}
	for role, name := range map[string]string{"subscription": p.PublicSubscriptionDomain(), "vpn": ingress.Domain, "backend": p.Bot.Domain} {
		t.Desired[role] = map[string]string{"name": strings.TrimSuffix(name, "."+dns.Zone), "data": ip.String()}
	}
	t.Variables = map[string]any{"ultra_lock_directory": releaseVariables["ultra_lock_directory"], "ultra_upgrade_domain_transaction": t.Binding, "ultra_upgrade_domain_desired": desired,
		"ultra_ingress":            map[string]any{"domain": ingress.Domain, "subscription_domain": p.PublicSubscriptionDomain(), "public_host": p.Bridge.PublicHost, "path": ingress.Path, "backend_port": e.BackendPort, "gateway_port": e.GatewayPort, "staging_port": ingress.StagingPort, "status_port": ingress.StatusPort, "experimental_port": ingress.ExperimentalPort, "forward_host": ingress.ForwardHost, "fingerprint": e.Fingerprint, "email": ingress.Email, "retain_aliases": true},
		"ultra_backup_state_paths": append([]string{}, p.Automation.StatePaths...), "ultra_backup_artifact_paths": append([]string{}, p.Automation.ArtifactPaths...),
		"ultra_ingress_email": ingress.Email, "ultra_ingress_domains": uniqueIngressDomains(p.PublicSubscriptionDomain(), ingress.Domain, p.Bot.Domain), "ultra_subscription_enabled": true, "ultra_subscription_domain": p.PublicSubscriptionDomain(), "ultra_bot_domain": p.Bot.Domain, "ultra_bot_port": p.Bot.Port, "ultra_bridge_url": p.Automation.BridgeURL, "ultra_bridge_ipv4": ip.String(), "ultra_cutover_contract_source": string(source),
		"ultra_backend_old_domain": e.Backend, "ultra_backend_old_public": e.Subscription, "ultra_backend_changed": t.BackendChanged, "ultra_backend_old_port": e.BotPort}
	return t, nil
}

func validateUpgradeDomainConfigPresence(p *installplan.InstallPlan) error {
	if p != nil && p.Automation != nil && (p.Automation.Ingress == nil || p.Automation.DNS == nil) {
		return errors.New("upgrade_domain_policy_removal_migration_required")
	}
	return nil
}

func validateUpgradePublicHostChange(previous, desired, vpnDomain, bridgeAddress string) error {
	if previous == desired || desired == vpnDomain {
		return nil
	}
	publicIP := net.ParseIP(desired)
	bridgeIP := net.ParseIP(bridgeAddress)
	if publicIP == nil || bridgeIP == nil || !publicIP.Equal(bridgeIP) {
		return errors.New("upgrade_domain_public_host_migration_required")
	}
	return nil
}

func upgradeBackupPathsChanged(e upgradeDomainEvidence) bool {
	return !e.StatePathsMatch || !e.ArtifactPathsMatch
}

func validateUpgradeDomainPolicy(e upgradeDomainEvidence, ingress *installplan.AutomationIngress, dns *installplan.AutomationDNS, automation *installplan.AutomationConfig) error {
	if ingress == nil || dns == nil || automation == nil {
		return errors.New("upgrade_domain_policy_required")
	}
	// Reject unsupported config-only deltas before the no-op return, so an
	// upgrade cannot succeed while leaving a requested policy change unapplied.
	if e.DNSTTL != dns.TTL {
		return errors.New("upgrade_domain_dns_ttl_migration_required")
	}
	if !e.ACMEEmailMatches {
		return errors.New("upgrade_domain_acme_email_migration_required")
	}
	if !e.IngressModeMatches || !e.ForwardHostMatches {
		return errors.New("upgrade_domain_ingress_mode_migration_required")
	}
	if (!e.StagingPortMatches && !e.StagingPortUnrecorded) || (e.StagingPortMatches && e.StagingPortUnrecorded) || !e.StatusPortMatches || !e.ExperimentalPortMatch {
		return errors.New("upgrade_domain_ingress_ports_migration_required")
	}
	if !e.AgeRecipientMatches {
		return errors.New("upgrade_domain_recovery_key_rotation_required")
	}
	if !e.BridgeProviderMatches || !e.StaticNodesMatch {
		return errors.New("upgrade_domain_automation_topology_migration_required")
	}
	if e.BridgeIPv4 != automation.BridgeIPv4 {
		return errors.New("upgrade_domain_bridge_address_migration_required")
	}
	if !e.AdminIDMatches {
		return errors.New("upgrade_domain_admin_identity_migration_required")
	}
	if e.BackendPort != ingress.BackendPort || e.GatewayPort != ingress.GatewayPort || (e.Fingerprint != "chrome" && e.Fingerprint != "firefox") {
		return errors.New("upgrade_domain_transport_migration_required")
	}
	return nil
}

func (t *upgradeDomainTransaction) phase(ctx context.Context, inventory map[string]any, directory, python, executable, action string, generation int) error {
	if t == nil || !t.Changed {
		return nil
	}
	if strings.HasSuffix(action, "-dns") || action == "prepare" || action == "promote" || action == "retire" {
		if !t.DNSChanged {
			return nil
		}
	}
	if err := t.loadAttempt(directory, generation); err != nil {
		return err
	}
	if action == "prepare" {
		raw, readErr := readBootstrapGenerationInput(filepath.Join(t.stage(directory, "rollback-dns", generation), "receipt.json"))
		if readErr == nil {
			var previous deployansible.Receipt
			if json.Unmarshal(raw, &previous) != nil {
				return errors.New("upgrade_domain_attempt_invalid")
			}
			if previous.State == "succeeded" {
				if err := t.phase(ctx, inventory, directory, python, executable, "rollback-dns", generation); err != nil {
					return err
				}
				t.Attempt++
				if t.Attempt > 1000 {
					return errors.New("upgrade_domain_attempt_limit")
				}
				marker, _ := json.Marshal(map[string]int{"version": 1, "generation": generation, "attempt": t.Attempt})
				if err := replaceUpgradeMetadata(filepath.Join(directory, fmt.Sprintf("domain-generation-%d.json", generation)), marker); err != nil {
					return err
				}
			}
		} else if !os.IsNotExist(readErr) {
			return readErr
		}
	}
	id := fmt.Sprintf("%s-domain-%d-attempt-%d", lifecycleID(directory), generation, t.Attempt)
	sum := sha256.Sum256([]byte(id))
	digest := hex.EncodeToString(sum[:])
	vars := map[string]any{}
	for k, v := range t.Variables {
		vars[k] = v
	}
	vars["ultra_ingress_transaction"] = "/var/lib/ultra-ingress/ansible-" + digest
	vars["ultra_backend_transaction"] = "/var/lib/ultra-ingress/backend-" + digest
	vars["ultra_upgrade_domain_action"] = action
	var op string
	if action == "prepare" || action == "promote" || action == "retire-dns" || action == "rollback-dns" {
		op = "upgrade-dns-migration"
		dnsAction := strings.TrimSuffix(action, "-dns")
		dnsSource, err := recoveryassets.Scripts.ReadFile("dns.py")
		if err != nil {
			return errors.New("upgrade_domain_dns_source_unavailable")
		}
		vars = map[string]any{"ultra_lock_directory": t.Variables["ultra_lock_directory"], "ultra_dns_migration_action": dnsAction, "ultra_dns_migration_operation_id": domainMigrationID(id), "ultra_dns_migration_desired": t.Desired, "ultra_dns_migration_application_source": string(dnsSource)}
		if action == "promote" || action == "retire-dns" {
			raw, err := readBootstrapGenerationInput(filepath.Join(t.stage(directory, "accept", generation), "receipt.json"))
			var receipt deployansible.Receipt
			if err != nil || json.Unmarshal(raw, &receipt) != nil || receipt.State != "succeeded" || receipt.Result.Values["verified"] != true {
				return errors.New("upgrade_domain_acceptance_required")
			}
			vars["ultra_dns_migration_acceptance_sha256"] = fmt.Sprintf("%x", sha256.Sum256(raw))
		}
	} else {
		if action != "apply" && action != "accept" && action != "rollback" && action != "retire" && action != "finalize" {
			return errors.New("upgrade_domain_phase_invalid")
		}
		op = "upgrade-domain"
		// Read the credential only inside the probe module. Immutable requests and
		// derived variable files contain the path and exact frozen digest alone.
		if action == "apply" || action == "accept" || action == "retire" {
			if t.ProbeSHA256 == "" {
				binding := filepath.Join(directory, "domain-probe.sha256")
				frozen, err := readBootstrapGenerationInput(binding)
				if os.IsNotExist(err) {
					_, checksum, readErr := readUpgradeDomainProbeInput(t.ProbeFile, t.Evidence.Subscription)
					if readErr != nil {
						return readErr
					}
					frozen = []byte(checksum)
					err = writeUpgradeInput(binding, frozen)
				}
				if err != nil || !regexp.MustCompile(`^[a-f0-9]{64}$`).Match(frozen) {
					return errors.New("upgrade_domain_probe_binding_invalid")
				}
				t.ProbeSHA256 = string(frozen)
			}
			vars["ultra_cutover_subscription_url_file"] = t.ProbeFile
			vars["ultra_cutover_subscription_url_sha256"] = t.ProbeSHA256
			vars["ultra_cutover_subscription_source_domain"] = t.Evidence.Subscription
		}
	}
	receipt, err := deployansible.RunLocalRetryFailed(ctx, op, inventory, vars, t.stage(directory, action, generation), python, executable)
	if err != nil {
		return err
	}
	if receipt.Result.Values["verified"] != true {
		return errors.New("upgrade_domain_phase_unverified")
	}
	if op == "upgrade-domain" && receipt.Result.Values["phase"] != action {
		return errors.New("upgrade_domain_phase_unverified")
	}
	if op == "upgrade-dns-migration" {
		expected := map[string]string{"prepare": "prepared", "promote": "promoted", "retire-dns": "retired", "rollback-dns": "rolled_back"}[action]
		if receipt.Result.Values["phase"] != expected {
			return errors.New("upgrade_domain_phase_unverified")
		}
	}
	return nil
}

func domainMigrationID(value string) string {
	sum := sha256.Sum256([]byte(value))
	sum[6] = (sum[6] & 15) | 0x50
	sum[8] = (sum[8] & 63) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

func upgradeDomainReleaseCommitted(directory string) bool {
	generation, err := upgradeActivationGeneration(directory, false)
	if err != nil {
		return false
	}
	raw, err := readBootstrapGenerationInput(filepath.Join(upgradeDependentStageDirectory(directory, "commit", generation), "receipt.json"))
	var receipt deployansible.Receipt
	return err == nil && json.Unmarshal(raw, &receipt) == nil && receipt.State == "succeeded" && receipt.Result.Values["verified"] == true
}

func (t *upgradeDomainTransaction) loadAttempt(directory string, generation int) error {
	path := filepath.Join(directory, fmt.Sprintf("domain-generation-%d.json", generation))
	raw, err := readBootstrapGenerationInput(path)
	if os.IsNotExist(err) {
		raw, _ = json.Marshal(map[string]int{"version": 1, "generation": generation, "attempt": 1})
		if err = writeUpgradeInput(path, raw); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	var marker struct {
		Version    int `json:"version"`
		Generation int `json:"generation"`
		Attempt    int `json:"attempt"`
	}
	if json.Unmarshal(raw, &marker) != nil || marker.Version != 1 || marker.Generation != generation || marker.Attempt < 1 || marker.Attempt > 1000 {
		return errors.New("upgrade_domain_attempt_invalid")
	}
	t.Attempt = marker.Attempt
	return nil
}
func (t *upgradeDomainTransaction) stage(directory, action string, generation int) string {
	step := "domain-" + action
	if t.Attempt > 1 {
		step += fmt.Sprintf("-attempt-%d", t.Attempt)
	}
	return upgradeDependentStageDirectory(directory, step, generation)
}
