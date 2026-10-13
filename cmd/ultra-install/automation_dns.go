package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/NikitaDmitryuk/ultra/deploy/recovery"
	"github.com/NikitaDmitryuk/ultra/internal/install"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
	"os"
	"path"
	"path/filepath"
)

// prepareDNSApply returns a remote program, invoked after published-ingress guards and before ACME.
func prepareDNSApply(p *installplan.InstallPlan) (string, func(), error) {
	noop := func() {}
	if p.Automation.DNS == nil {
		return "", noop, nil
	}
	if p.Automation.Ingress == nil || p.Automation.Ingress.ForwardHost != "" {
		return "", noop, errors.New("managed DNS requires direct bridge ingress")
	}
	local, err := os.MkdirTemp("", "ultra-dns-")
	if err != nil {
		return "", noop, err
	}
	cleanupLocal := func() { _ = os.RemoveAll(local) }
	_, key, err := prepareProviderSecrets(p, local)
	if err != nil {
		cleanupLocal()
		return "", noop, err
	}
	remote := path.Join("/var/lib/ultra-automation/staging", filepath.Base(local))
	ssh := func(command string) error {
		return install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, command)
	}
	cleanup := func() { _ = ssh("rm -rf -- " + shellQuote(remote)); cleanupLocal() }
	if err := ssh("install -d -m 700 " + shellQuote(remote)); err != nil {
		cleanup()
		return "", noop, errors.New("DNS staging unavailable")
	}
	if err := install.SCP(p.SSH.Identity, key, p.SSH.User, p.Bridge.SSHHost, path.Join(remote, "dns-key")); err != nil {
		cleanup()
		return "", noop, errors.New("DNS credential projection failed")
	}
	policy := *p.Automation.DNS
	policy.APIKeyFile = "/etc/ultra-recovery/dns-api-key"
	desired := map[string]any{"subscription": map[string]string{"name": policy.SubscriptionName, "data": p.Automation.BridgeIPv4}, "vpn": map[string]string{"name": policy.VPNName, "data": p.Automation.BridgeIPv4}}
	encoded, _ := json.Marshal(map[string]any{"config": policy, "desired": desired})
	source, err := recoveryassets.Scripts.ReadFile("dns.py")
	if err != nil {
		cleanup()
		return "", noop, err
	}
	script := "dns_scope={}\nexec(compile(base64.b64decode(" + pythonString(base64.StdEncoding.EncodeToString(source)) + "),'dns','exec'),dns_scope)\n"
	script += "dns_policy=json.loads(" + pythonString(string(encoded)) + ")\n"
	script += "from pathlib import Path\nimport os\nPath('/etc/ultra-recovery').mkdir(mode=0o700,parents=True,exist_ok=True)\nos.chmod('/etc/ultra-recovery',0o700)\nsubscription_scope['atomic'](Path('/etc/ultra-recovery/dns-api-key'),Path(" + pythonString(path.Join(remote, "dns-key")) + ").read_bytes(),0o600)\n"
	script += "dns_scope['save']('/etc/ultra-recovery/dns.json',dns_policy)\ndns_scope['execute'](dns_policy['config'],dns_policy['desired'],'/etc/ultra-recovery/dns-receipt.json')\n"
	script += "scope['run'](['apt-get','install','-y','-qq','dnsutils'])\ndns_scope['wait_ready'](dns_policy['config'],dns_policy['desired'])\n"
	return script, cleanup, nil
}
