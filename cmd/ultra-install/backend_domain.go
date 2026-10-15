package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	recoveryassets "github.com/NikitaDmitryuk/ultra/deploy/recovery"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func runBackendDomainCommand(args []string) {
	fs := flag.NewFlagSet("backend-domain", flag.ExitOnError)
	file := fs.String("config", "install.config", "canonical deployment parameters")
	domain := fs.String("domain", "", "distinct owned backend TLS hostname")
	zone := fs.String("zone", "", "existing managed DNS zone")
	action := fs.String("action", "apply", "apply, accept, rollback or accept-rollback; only acceptance updates canonical BOT_DOMAIN")
	previous := fs.String("previous-domain", "", "previous backend name; required when canonical config already has the target and for rollback after acceptance")
	pins := fs.String("known-hosts", "", "verified absolute SSH known_hosts file")
	email := fs.String("acme-email", "", "ACME email, defaults to canonical ACME_EMAIL")
	_ = fs.Parse(args)
	p, err := installplan.LoadLegacyEnvConfig(*file)
	exitOnErr("backend config", err)
	values, err := installplan.ReadSecretsFile(*file)
	exitOnErr("backend parameters", err)
	if *email == "" {
		*email = values["ACME_EMAIL"]
	}
	if *pins == "" && p.Automation != nil {
		*pins = p.Automation.KnownHostsFile
	}
	exitOnErr("backend domain", applyBackendDomain(p, *file, *domain, *zone, *action, *previous, *pins, *email))
}

func backendDomainPolicy(p *installplan.InstallPlan, domain, zone, action, previous, pins, email string) (map[string]any, error) {
	label := regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	validHost := func(name string) bool {
		if len(name) > 253 || !strings.Contains(name, ".") {
			return false
		}
		for _, part := range strings.Split(name, ".") {
			if !label.MatchString(part) {
				return false
			}
		}
		return true
	}
	old := p.Bot.Domain
	if previous != "" {
		if p.Bot.Domain != previous && p.Bot.Domain != domain {
			return nil, errors.New("canonical backend does not match migration")
		}
		old = previous
	}
	if p.Automation == nil || p.Automation.Ingress == nil || p.Automation.DNS == nil {
		return nil, errors.New("backend migration requires existing managed public ingress and DNS")
	}
	public, vpn := p.PublicSubscriptionDomain(), p.Automation.Ingress.Domain
	if !validHost(zone) || !validHost(domain) || !validHost(old) || !validHost(public) || !validHost(vpn) || !strings.HasSuffix(domain, "."+zone) || !label.MatchString(strings.TrimSuffix(domain, "."+zone)) || zone != p.Automation.DNS.Zone {
		return nil, errors.New("backend hostname must be one label in the existing managed zone")
	}
	if domain == old || domain == public || domain == vpn || !filepath.IsAbs(pins) || !strings.Contains(email, "@") || strings.ContainsAny(email, "\r\n\x00") {
		return nil, errors.New("distinct backend, pinned SSH and ACME email required")
	}
	if action != "apply" && action != "accept" && action != "rollback" && action != "accept-rollback" {
		return nil, errors.New("invalid backend action")
	}
	address := net.ParseIP(p.Bridge.Address)
	if address == nil || address.To4() == nil {
		return nil, errors.New("explicit bridge IPv4 required")
	}
	source, err := recoveryassets.Scripts.ReadFile("dns.py")
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(p.Bridge.SSHHost + "|" + old + "|" + domain + "|" + public + "|" + vpn + "|" + zone))
	return map[string]any{
		"ultra_backend_action": action, "ultra_backend_domain": domain, "ultra_backend_old_domain": old,
		"ultra_backend_zone": zone, "ultra_backend_email": email, "ultra_backend_vpn_domain": vpn,
		"ultra_subscription_domain": public, "ultra_bridge_ipv4": address.String(),
		"ultra_backend_transaction": "/var/lib/ultra-ingress/backend-" + hex.EncodeToString(sum[:]),
		"ultra_dns_source_content":  string(source),
	}, nil
}

func applyBackendDomain(p *installplan.InstallPlan, file, domain, zone, action, previous, pins, email string) error {
	variables, err := backendDomainPolicy(p, domain, zone, action, previous, pins, email)
	if err != nil {
		return err
	}
	if err = os.Setenv("ULTRA_INSTALL_SSH_KNOWN_HOSTS", pins); err != nil {
		return err
	}
	stateRoot, err := bootstrapStateRoot()
	if err != nil {
		return err
	}
	if err = ensurePrivateBootstrapDirectory(stateRoot); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(variables["ultra_backend_transaction"].(string)))
	planRoot := filepath.Join(stateRoot, "backend-domain-"+hex.EncodeToString(sum[:]))
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
	executable, err := resolveAnsibleRuntime(ctx, p, stateRoot, os.Getenv("ULTRA_ANSIBLE_EXECUTABLE"))
	if err != nil {
		return err
	}
	runtimeRelease, err := pinOperatorRuntimeForOperation(directory, executable)
	if err != nil {
		return err
	}
	defer runtimeRelease()
	ctx, release, err := withFrozenLifecycleLock(ctx, p, lockDirectory, directory)
	if err != nil {
		return err
	}
	defer release()
	bridge := *p
	bridge.Exits = nil
	bridge.Database.Enabled = false
	if bridge.Automation != nil {
		automation := *bridge.Automation
		automation.KnownHostsFile = pins
		bridge.Automation = &automation
	}
	inventory, err := bootstrapInventory(&bridge, directory)
	if err != nil {
		return err
	}
	python := "/usr/bin/python3"
	if err = ansibleLifecycle(ctx, p, inventory, directory, python, executable, "applying", true); err != nil {
		return err
	}
	variables["ultra_lock_directory"] = lockDirectory
	if err = runBackendDomainStage(ctx, inventory, variables, directory, python, executable); err != nil {
		if action != "apply" {
			return err
		}
		// A failed playbook may have restored the old backend, but its failed
		// receipt cannot prove that recovery completed. Verify an explicit
		// rollback before reopening the fleet; retain the lease if it fails.
		// Before journal creation, rollback instead proves the backend is still
		// old and verifies live ingress without restarting unchanged services.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
		rollback := make(map[string]any, len(variables))
		for key, value := range variables {
			rollback[key] = value
		}
		rollback["ultra_backend_action"] = "rollback"
		if recoveryErr := runBackendDomainStage(cleanup, inventory, rollback, directory, python, executable); recoveryErr != nil {
			return errors.Join(err, fmt.Errorf("backend rollback unconfirmed; retry apply or rollback with the same migration: %w", recoveryErr))
		}
		if releaseErr := ansibleLifecycle(cleanup, p, inventory, directory, python, executable, "released", false); releaseErr != nil {
			return errors.Join(err, releaseErr)
		}
		return errors.Join(err, completeBootstrapAttempt(planRoot, directory))
	}
	if action == "accept" || action == "accept-rollback" {
		accepted := domain
		if action == "accept-rollback" {
			accepted = variables["ultra_backend_old_domain"].(string)
		}
		if err = writeCutoverConfig(file, map[string]string{"BOT_DOMAIN": accepted}); err != nil {
			return errors.New("backend verified but canonical update failed; repeat acceptance with original --previous-domain")
		}
	}
	if err = ansibleLifecycle(ctx, p, inventory, directory, python, executable, "released", false); err != nil {
		return err
	}
	if err = completeBootstrapAttempt(planRoot, directory); err != nil {
		return err
	}
	fmt.Println("backend domain " + action + ": verified; public ingress preserved")
	return nil
}

// Keep the durable attempt (and its lifecycle identity) across interrupted or
// failed actions, but never reuse an immutable job receipt for a new action.
// Remote backend state is journalled independently and safely resumes/reverts.
func runBackendDomainStage(ctx context.Context, inventory, variables map[string]any, directory, python, executable string) error {
	stage, err := os.MkdirTemp(directory, "backend-"+variables["ultra_backend_action"].(string)+"-")
	if err != nil {
		return err
	}
	if err = os.Remove(stage); err != nil {
		return err
	}
	receipt, err := deployansible.RunLocal(ctx, "backend-domain", inventory, variables, stage, python, executable)
	if err != nil {
		return err
	}
	if verified, _ := receipt.Result.Values["verified"].(bool); !verified {
		return errors.New("backend operation verification missing")
	}
	return nil
}
