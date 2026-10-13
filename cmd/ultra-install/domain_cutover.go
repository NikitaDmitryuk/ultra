package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/NikitaDmitryuk/ultra/deploy"
	recoveryassets "github.com/NikitaDmitryuk/ultra/deploy/recovery"
	"github.com/NikitaDmitryuk/ultra/internal/install"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func runDomainCutoverCommand(args []string) {
	fs := flag.NewFlagSet("domain-cutover", flag.ExitOnError)
	file := fs.String("config", "install.config", "canonical deployment parameters (v1/v2)")
	subscription := fs.String("subscription-domain", "", "new owned subscription hostname")
	vpn := fs.String("vpn-domain", "", "new owned XHTTP hostname")
	zone := fs.String("zone", "", "existing owned Vultr zone")
	receipt := fs.String("dns-receipt", "", "existing private owned DNS receipt")
	pins := fs.String("known-hosts", "", "verified SSH known_hosts (required for legacy configs)")
	email := fs.String("acme-email", "", "ACME account email (or ACME_EMAIL in config)")
	_ = fs.Parse(args)
	values, err := installplan.ReadSecretsFile(*file)
	exitOnErr("cutover config", err)
	p, err := installplan.LoadLegacyEnvConfig(*file)
	exitOnErr("cutover config", err)
	if *pins == "" && p.Automation != nil {
		*pins = p.Automation.KnownHostsFile
	}
	if *email == "" {
		*email = values["ACME_EMAIL"]
	}
	exitOnErr("domain cutover", applyDomainCutover(p, *file, *subscription, *vpn, *zone, *receipt, *pins, *email))
}

func cutoverDelta(subscription, vpn, zone string) map[string]string {
	return map[string]string{"SUBSCRIPTION_DOMAIN": subscription, "VPN_DOMAIN": vpn, "PUBLIC_HOST": vpn,
		"DNS_PROVIDER": "vultr", "DNS_ZONE": zone, "DNS_TTL": "300", "DNS_SUBSCRIPTION_NAME": strings.TrimSuffix(subscription, "."+zone), "DNS_VPN_NAME": strings.TrimSuffix(vpn, "."+zone), "SUBSCRIPTION_INGRESS_MODE": "direct"}
}

func writeCutoverConfig(file string, delta map[string]string) error {
	info, err := os.Lstat(file)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("canonical config must be regular")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	present := map[string]bool{}
	for index, line := range lines {
		key, _, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if value, exists := delta[key]; exists {
			lines[index] = key + "=" + value
			present[key] = true
		}
	}
	keys := []string{}
	for key := range delta {
		if !present[key] {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		lines = append(lines, key+"="+delta[key])
	}
	data := []byte(strings.Join(lines, "\n") + "\n")
	if string(raw) == string(data) {
		return nil
	}
	backup := file + ".before-domain-cutover"
	f, err := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		_, writeErr := f.Write(raw)
		syncErr := f.Sync()
		closeErr := f.Close()
		if writeErr != nil {
			return writeErr
		}
		if syncErr != nil {
			return syncErr
		}
		if closeErr != nil {
			return closeErr
		}
	} else if !os.IsExist(err) {
		return err
	}
	f, err = os.CreateTemp(filepath.Dir(file), ".ultra-cutover-config-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) //nolint:errcheck
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), file); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(file))
	if err != nil {
		return err
	}
	defer directory.Close() //nolint:errcheck
	return directory.Sync()
}

func applyDomainCutover(p *installplan.InstallPlan, configFile, subscription, vpn, zone, receipt, pins, email string) error {
	label := regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	if !strings.Contains(zone, ".") || len(zone) > 253 {
		return errors.New("invalid cutover zone")
	}
	for _, part := range strings.Split(zone, ".") {
		if !label.MatchString(part) {
			return errors.New("invalid cutover zone")
		}
	}
	for _, domain := range []string{subscription, vpn} {
		if !strings.HasSuffix(domain, "."+zone) || !label.MatchString(strings.TrimSuffix(domain, "."+zone)) {
			return errors.New("cutover domains must be distinct relative labels in owned zone")
		}
	}
	if subscription == vpn || !filepath.IsAbs(pins) || !filepath.IsAbs(receipt) || !strings.Contains(email, "@") {
		return errors.New("cutover requires distinct hostnames, pinned SSH, ownership receipt and ACME email")
	}
	bridgeIP := net.ParseIP(p.Bridge.SSHHost)
	if bridgeIP == nil || bridgeIP.To4() == nil {
		return errors.New("cutover bridge SSH host must be explicit IPv4")
	}
	if err := os.Setenv("ULTRA_INSTALL_SSH_STRICT_HOST_KEY", "yes"); err != nil {
		return err
	}
	if err := os.Setenv("ULTRA_INSTALL_SSH_KNOWN_HOSTS", pins); err != nil {
		return err
	}
	existing, err := loadPlanRemoteBridgeSpec(p)
	if err != nil {
		return errors.New("cutover existing spec unavailable")
	}
	if !existing.PrimaryXHTTPIsPublished() {
		return errors.New("cutover requires existing published primary")
	}
	secrets, err := installplan.ReadSecretsFile(p.SecretsEnvFile())
	if err != nil {
		return errors.New("canonical cutover secrets unavailable")
	}
	url := strings.TrimSpace(secrets["ULTRA_CUTOVER_SUBSCRIPTION_URL"])
	key := strings.TrimSpace(secrets["ULTRA_VULTR_DNS_API_KEY"])
	if url == "" || key == "" || strings.ContainsAny(url+key, "\r\n\x00") {
		return errors.New("canonical cutover probe URL and DNS key required")
	}
	local, err := os.MkdirTemp("", "ultra-domain-cutover-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(local) //nolint:errcheck
	remote := path.Join("/var/lib/ultra-automation/staging", filepath.Base(local))
	ssh := func(command string) error {
		return install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, command)
	}
	if err = ssh("install -d -m 700 " + shellQuote(remote)); err != nil {
		return err
	}
	defer func() { _ = ssh("rm -rf -- " + shellQuote(remote)) }()
	upload := func(name string, data []byte) error {
		file := filepath.Join(local, name)
		if err := os.WriteFile(file, data, 0600); err != nil {
			return err
		}
		return install.SCP(p.SSH.Identity, file, p.SSH.User, p.Bridge.SSHHost, path.Join(remote, name))
	}
	for _, name := range []string{"domain_cutover.py", "dns.py"} {
		data, err := recoveryassets.Scripts.ReadFile(name)
		if err != nil {
			return err
		}
		if err = upload(name, data); err != nil {
			return err
		}
	}
	for name, data := range map[string][]byte{"bridge_subscription.py": []byte(deploy.BridgeSubscriptionIngress), "xhttp_ingress.py": []byte(install.XHTTPIngressScript), "subscription-url": []byte(url), "dns-key": []byte(key)} {
		if err = upload(name, data); err != nil {
			return err
		}
	}
	receiptData, err := os.ReadFile(receipt)
	if err != nil {
		return errors.New("owned DNS receipt unavailable")
	}
	if err = upload("dns-receipt.json", receiptData); err != nil {
		return err
	}
	desired := map[string]any{"subscription": map[string]string{"name": strings.TrimSuffix(subscription, "."+zone), "data": bridgeIP.String()}, "vpn": map[string]string{"name": strings.TrimSuffix(vpn, "."+zone), "data": bridgeIP.String()}}
	params := map[string]any{"bridge_ipv4": bridgeIP.String(), "subscription_domain": subscription, "subscription_url_file": path.Join(remote, "subscription-url"), "dns_key_source": path.Join(remote, "dns-key"), "dns_receipt_source": path.Join(remote, "dns-receipt.json"), "dns": map[string]any{"provider": "vultr", "zone": zone, "ttl": 300, "subscription_name": strings.TrimSuffix(subscription, "."+zone), "vpn_name": strings.TrimSuffix(vpn, "."+zone), "api_key_file": "/etc/ultra-recovery/dns-api-key"}, "desired": desired, "ingress": map[string]any{"domain": vpn, "public_host": vpn, "path": existing.PrimaryXHTTP.Path, "backend_port": existing.PrimaryXHTTP.BackendPort, "email": email}}
	raw, _ := json.Marshal(params)
	if err = upload("cutover.json", raw); err != nil {
		return err
	}
	if err = ssh("python3 " + shellQuote(path.Join(remote, "domain_cutover.py")) + " --config " + shellQuote(path.Join(remote, "cutover.json"))); err != nil {
		return errors.New("domain cutover not completed; resume with same target parameters")
	}
	delta := cutoverDelta(subscription, vpn, zone)
	delta["ACME_EMAIL"] = email
	delta["PUBLIC_XHTTP_PATH"] = existing.PrimaryXHTTP.Path
	if err = writeCutoverConfig(configFile, delta); err != nil {
		return errors.New("cutover completed but canonical config write failed; repeat the same command")
	}
	fmt.Println("domain cutover complete; old ingress preserved; canonical parameters updated")
	return nil
}
