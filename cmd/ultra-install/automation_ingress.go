package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/NikitaDmitryuk/ultra/deploy"
	"github.com/NikitaDmitryuk/ultra/internal/install"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func automationIngress(p *installplan.InstallPlan, activate bool) error {
	i := p.Automation.Ingress
	if i == nil {
		return nil
	} // Reused published ingress remains authoritative.
	if !activate && i.ForwardHost != "" {
		if err := install.SetupFirewallPorts(p.SSH.User, i.ForwardHost, p.SSH.Identity, []int{80, 443, 8444}); err != nil {
			return errors.New("forward ingress firewall unavailable")
		}
		settings, _ := json.Marshal(map[string]any{"bridge": p.Automation.BridgeIPv4, "domain": p.Bot.Domain, "prepare_stream": true})
		preparation := `import pathlib,subprocess
subprocess.run(['apt-get','update','-qq'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
subprocess.run(['apt-get','install','-y','-qq','nginx','libnginx-mod-stream'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
`
		script := preparation + "\nsettings=json.loads(" + pythonString(string(settings)) + ")\n" + deploy.SubscriptionIngressSSH
		// json must be imported before assigning settings; the embedded module imports it too.
		script = "import json\n" + script
		command := automationPythonCommand(script)
		if err := install.RunSSH(p.SSH.User, i.ForwardHost, p.SSH.Identity, command); err != nil {
			return errors.New("forward ingress setup failed")
		}
	}
	raw, _ := json.Marshal(i)
	setup := "import base64,json\np=json.loads(" + pythonString(string(raw)) + ")\np['binary']='/usr/local/bin/ultra-relay'\n"
	setup += "scope={'__name__':'ultra_ingress'}\nexec(compile(" + pythonBytes([]byte(install.XHTTPIngressScript)) + ",'ingress','exec'),scope)\nscope['validate'](p)\n"
	setup += "subscription_scope={'__name__':'ultra_subscription'}\nexec(compile(" + pythonBytes([]byte(deploy.BridgeSubscriptionIngress)) + ",'subscription','exec'),subscription_scope)\n"
	setup += "current=json.loads(scope['SPEC'].read_text())\npublished=subscription_scope['check_published'](current,p)\n"
	if activate {
		setup += "if not published:\n scope['apply'](p,'stage')\n scope['apply'](p,'activate')\n"

		if i.ForwardHost == "" {
			if p.PublicSubscriptionDomain() == i.Domain {
				return errors.New("subscription and VPN ingress require distinct domains")
			}
			subscription, _ := json.Marshal(map[string]any{"domain": p.PublicSubscriptionDomain(), "upstream_domain": p.Bot.Domain, "bot_port": p.Bot.Port})
			setup += "subscription_scope['install'](json.loads(" + pythonString(string(subscription)) + "))\n"
		}
	} else {
		dnsProgram, cleanup, err := prepareDNSApply(p)
		if err != nil {
			return err
		}
		defer cleanup()
		setup += dnsProgram
		setup += "root=scope['ROOT'];root.mkdir(parents=True,exist_ok=True)\nmanifest=json.loads(scope['MANIFEST'].read_text()) if scope['MANIFEST'].exists() else {}\nscope['prepare_certificate'](p,manifest)\n"
		if p.PublicSubscriptionDomain() != p.Bot.Domain && p.PublicSubscriptionDomain() != i.Domain {
			setup += "subscription_cert=dict(p,domain=" + pythonString(p.PublicSubscriptionDomain()) + ")\nscope['prepare_certificate'](subscription_cert,manifest)\n"
		}
		if p.Bot.Domain != "" && p.Bot.Domain != i.Domain {
			setup += "bot=dict(p,domain=" + pythonString(p.Bot.Domain) + ")\nscope['prepare_certificate'](bot,manifest)\n"
		}
	}
	return install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, automationPythonCommand(setup))
}
func pythonString(value string) string { raw, _ := json.Marshal(value); return string(raw) }

func automationPythonCommand(source string) string {
	// Only the base64 alphabet crosses the shell/Python source boundary.
	return "python3 -c " + shellQuote("import base64;exec(compile("+pythonBytes([]byte(source))+",'ultra-install','exec'))")
}

func pythonBytes(value []byte) string {
	return `base64.b64decode("` + base64.StdEncoding.EncodeToString(value) + `")`
}
