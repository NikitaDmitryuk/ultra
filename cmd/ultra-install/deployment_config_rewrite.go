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
	provider := flags.String("provider", "", "new primary provider")
	_ = flags.Parse(args)
	exitOnErr("deployment config rewrite", rewriteDeploymentConfig(*input, *output, *old, *bridge, *ssh, *public, *subscription, *provider))
}
func rewriteDeploymentConfig(input, output, old, bridge, ssh, public, subscription, provider string) error {
	if net.ParseIP(old).To4() == nil || net.ParseIP(bridge).To4() == nil || !regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`).MatchString(ssh) || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`).MatchString(provider) {
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
	p, err := installplan.LoadConfig(input)
	if err != nil {
		return err
	}
	values := p.SourceValues
	if len(values) == 0 {
		return errors.New("deployment_rewrite_canonical_source_required")
	}
	values["BRIDGE"] = bridge
	values["BRIDGE_SSH_HOST"] = ssh
	if _, exists := values["FRONT"]; exists {
		values["FRONT"] = bridge
	}
	if values["DB_HOST"] == old || values["DB_HOST"] == p.Bridge.SSHHost {
		values["DB_HOST"] = bridge
	}
	values["PUBLIC_HOST"] = public
	values["SUBSCRIPTION_DOMAIN"] = subscription
	values["ULTRA_AUTOMATION_BRIDGE_IPV4"] = bridge
	values["ULTRA_AUTOMATION_BRIDGE_PROVIDER"] = strings.ToLower(provider)
	if previous, err := url.Parse(values["ULTRA_AUTOMATION_BRIDGE_URL"]); err == nil && previous.Scheme == "https" && previous.Hostname() != "" && previous.User == nil {
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
