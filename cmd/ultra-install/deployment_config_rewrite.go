package main

import (
	"errors"
	"flag"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func runDeploymentConfigRewrite(args []string) {
	flags := flag.NewFlagSet("rewrite-deployment-config", flag.ExitOnError)
	input := flags.String("input", "", "restored canonical config")
	output := flags.String("output", "", "private rewritten config")
	old := flags.String("old-bridge", "", "fenced source address")
	bridge := flags.String("new-bridge", "", "new bridge IPv4")
	ssh := flags.String("new-ssh-host", "", "current target operator endpoint")
	public := flags.String("public-host", "", "restored client name")
	subscription := flags.String("subscription-domain", "", "restored subscription name")
	database := flags.String("database-ip", "", "selected dedicated database IPv4")
	provider := flags.String("provider", "", "new primary provider")
	_ = flags.Parse(args)
	exitOnErr(
		"deployment config rewrite",
		rewriteDeploymentConfig(*input, *output, *old, *bridge, *ssh, *public, *subscription, *provider, *database),
	)
}
func rewriteDeploymentConfig(input, output, old, bridge, ssh, public, subscription, provider, database string) error {
	if net.ParseIP(database).To4() == nil || database == bridge || database == ssh {
		return errors.New("deployment_rewrite_dedicated_database_invalid")
	}
	if net.ParseIP(old).To4() == nil || net.ParseIP(bridge).To4() == nil || !regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`).MatchString(ssh) ||
		!regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`).MatchString(provider) {
		return errors.New("deployment_rewrite_identity_invalid")
	}
	for _, domain := range []string{public, subscription} {
		if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*$`).MatchString(domain) {
			return errors.New("deployment_rewrite_public_name_invalid")
		}
	}
	info, err := os.Lstat(input)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 {
		return errors.New("deployment_rewrite_private_source_required")
	}
	// Older encrypted generations may contain the retired automatic-channel
	// policy in their canonical input. Strip only that known obsolete namespace
	// during restore; ordinary installs still reject it.
	values, err := installplan.ReadSecretsFile(input)
	if err != nil {
		return err
	}
	for key := range values {
		if strings.HasPrefix(key, "ULTRA_AUTO_UPGRADE_") {
			delete(values, key)
		}
	}
	delete(values, "DATABASE_DUMP")
	values["DATABASE_IP"] = database
	if values["MAIN_EXIT_IP"] == database {
		return errors.New("deployment_rewrite_dedicated_database_invalid")
	}
	p, err := installplan.CanonicalValuesToPlan(values)
	if err != nil {
		return err
	}
	if len(p.SourceValues) == 0 {
		return errors.New("deployment_rewrite_canonical_source_required")
	}
	values["BRIDGE_IP"] = bridge
	if ssh != bridge {
		return errors.New("canonical bridge SSH endpoint must equal BRIDGE_IP")
	}
	values["PUBLIC_HOST"] = public
	values["SUBSCRIPTION_DOMAIN"] = subscription
	delete(values, "ULTRA_AUTOMATION_BRIDGE_IPV4")
	values["ULTRA_AUTOMATION_BRIDGE_PROVIDER"] = strings.ToLower(provider)
	if previous, err := url.Parse(values["ULTRA_AUTOMATION_BRIDGE_URL"]); err == nil && previous.Scheme == "https" &&
		previous.Hostname() != "" &&
		previous.User == nil {
		previous.Host = subscription
		values["ULTRA_AUTOMATION_BRIDGE_URL"] = previous.String()
	} else {
		values["ULTRA_AUTOMATION_BRIDGE_URL"] = "https://" + subscription + "/healthz"
	}
	rendered, err := renderCanonicalInputs(values)
	if err != nil {
		return err
	}
	return replaceUpgradeMetadata(output, rendered)
}
