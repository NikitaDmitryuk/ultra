package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
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

func cutoverDelta(subscription, vpn, zone string, publicHosts ...string) map[string]string {
	publicHost := vpn
	if len(publicHosts) > 0 && publicHosts[0] != "" {
		publicHost = publicHosts[0]
	}
	return map[string]string{"SUBSCRIPTION_DOMAIN": subscription, "VPN_DOMAIN": vpn, "PUBLIC_HOST": publicHost,
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
	mode := info.Mode().Perm()
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
	if err = f.Chmod(mode); err == nil {
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
	bridgeIP := net.ParseIP(p.Bridge.Address)
	if bridgeIP == nil || bridgeIP.To4() == nil {
		return errors.New("cutover bridge address must be explicit IPv4")
	}
	if err := os.Setenv("ULTRA_INSTALL_SSH_KNOWN_HOSTS", pins); err != nil {
		return err
	}
	stateRoot, err := bootstrapStateRoot()
	if err != nil {
		return err
	}
	if err = ensurePrivateBootstrapDirectory(stateRoot); err != nil {
		return err
	}
	fingerprint := sha256.Sum256([]byte(p.Bridge.SSHHost + "|" + subscription + "|" + vpn + "|" + zone + "|" + email))
	planRoot := filepath.Join(stateRoot, "domain-cutover-"+hex.EncodeToString(fingerprint[:]))
	if err = ensurePrivateBootstrapDirectory(planRoot); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, operatorRelease, err := withBootstrapOperatorLock(ctx, stateRoot)
	if err != nil {
		return err
	}
	defer operatorRelease()
	directory, err := beginBootstrapAttempt(planRoot)
	if err != nil {
		return err
	}
	lockDirectory, err := freezeBootstrapExecution(p, directory, stateRoot)
	if err != nil {
		return err
	}
	ctx, release, err := withFrozenLifecycleLock(ctx, p, lockDirectory, directory)
	if err != nil {
		return err
	}
	defer release()
	bridgeOnly := *p
	bridgeOnly.Exits = nil
	bridgeOnly.Database.Enabled = false
	if bridgeOnly.Automation != nil {
		a := *bridgeOnly.Automation
		a.KnownHostsFile = pins
		bridgeOnly.Automation = &a
	}
	python := "/usr/bin/python3"
	executable := os.Getenv("ULTRA_ANSIBLE_EXECUTABLE")
	if executable == "" {
		executable = "/opt/ultra-ansible/current/venv/bin/ansible-playbook"
	}
	gateInventory, err := bootstrapInventory(&bridgeOnly, directory)
	if err != nil {
		return err
	}
	if err = ansibleLifecycle(ctx, p, gateInventory, directory, python, executable, "applying", true); err != nil {
		return err
	}
	inventory, inspection, err := inspectBootstrap(ctx, &bridgeOnly, directory, python, executable, lockDirectory)
	if err != nil {
		return err
	}
	specJSON, err := inspection["bridge"].file("spec.json")
	if err != nil {
		return err
	}
	var existing config.Spec
	if err = json.Unmarshal(specJSON, &existing); err != nil {
		return errors.New("cutover existing spec unavailable")
	}
	if !existing.PrimaryXHTTPIsPublished() {
		return errors.New("cutover requires existing published primary")
	}
	secrets, err := installplan.ReadSecretsFile(p.SecretsEnvFile())
	if err != nil {
		return errors.New("canonical cutover secrets unavailable")
	}
	url, key, err := domainCutoverProbeInputs(secrets)
	if err != nil {
		return err
	}
	receiptInfo, err := os.Lstat(receipt)
	if err != nil || !receiptInfo.Mode().IsRegular() || receiptInfo.Mode().Perm()&0077 != 0 {
		return errors.New("private owned DNS receipt required")
	}
	receiptData, err := os.ReadFile(receipt)
	if err != nil {
		return errors.New("owned DNS receipt unavailable")
	}
	var owned map[string]any
	if err = json.Unmarshal(receiptData, &owned); err != nil {
		return errors.New("owned DNS receipt invalid")
	}
	environment, err := inspection["bridge"].file("environment")
	if err != nil {
		return err
	}
	botDomain := p.Bot.Domain
	botPort := p.Bot.Port
	if botPort == 0 {
		botPort = 8444
	}
	for _, line := range strings.Split(string(environment), "\n") {
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(value, "\"'")
		if name == "ULTRA_BOT_DOMAIN" {
			botDomain = value
		}
		if name == "ULTRA_BOT_PORT" {
			botPort, err = strconv.Atoi(value)
			if err != nil {
				return errors.New("invalid existing bot port")
			}
		}
	}
	publicHost := strings.TrimSpace(p.Bridge.PublicHost)
	if publicHost == "" {
		publicHost = vpn
	}
	if p.Automation == nil || p.Automation.Ingress == nil {
		return errors.New("domain cutover requires canonical ingress policy")
	}
	variables, err := buildDomainCutoverVariables(domainCutoverDesired{
		Subscription: subscription, VPN: vpn, PublicHost: publicHost, Zone: zone,
		Email: email, BotDomain: botDomain, BotPort: botPort, BridgeIPv4: bridgeIP.String(),
		StagingPort: p.Automation.Ingress.StagingPort, StatusPort: p.Automation.Ingress.StatusPort,
		ExperimentalPort: p.Automation.Ingress.ExperimentalPort,
	}, &existing, directory, lockDirectory, url, key, owned)
	if err != nil {
		return err
	}
	_, err = deployansible.RunLocal(ctx, "domain-cutover", inventory, variables, filepath.Join(directory, "apply"), python, executable)
	if err != nil {
		return err
	}
	delta := cutoverDelta(subscription, vpn, zone, publicHost)
	delta["ACME_EMAIL"] = email
	delta["PUBLIC_XHTTP_PATH"] = existing.PrimaryXHTTP.Path
	if err = writeCutoverConfig(configFile, delta); err != nil {
		return errors.New("cutover completed but canonical config write failed; repeat the same command")
	}
	if err = ansibleLifecycle(ctx, p, inventory, directory, python, executable, "released", false); err != nil {
		return err
	}
	if err = completeBootstrapAttempt(planRoot, directory); err != nil {
		return err
	}
	fmt.Println("domain cutover complete; old ingress preserved; canonical parameters updated")
	return nil
}

func domainCutoverProbeInputs(secrets map[string]string) (string, string, error) {
	url := strings.TrimSpace(secrets["ULTRA_SUBSCRIPTION_PROBE_URL"])
	key := strings.TrimSpace(secrets["ULTRA_VULTR_DNS_API_KEY"])
	if url == "" || key == "" || strings.ContainsAny(url+key, "\r\n\x00") {
		return "", "", errors.New("canonical subscription probe URL and DNS key required")
	}
	return url, key, nil
}

func parseCutoverPoll(output string) (unit, phase string) {
	for _, line := range strings.Split(output, "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "ULTRA_UNIT="); ok {
			unit = strings.TrimSpace(value)
		}
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "ULTRA_PHASE="); ok {
			phase = strings.TrimSpace(value)
		}
	}
	return unit, phase
}
