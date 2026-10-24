package installplan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

type DoctorOptions struct {
	CheckSSH   func(user, host, identity string) bool
	LookupHost func(ctx context.Context, host string) ([]string, error)
	DialTCP    func(ctx context.Context, host string, port int) error
	EnvRoot    string
}

func Doctor(ctx context.Context, p *InstallPlan, opts DoctorOptions) DoctorReport {
	var issues []Issue
	if err := ValidatePlan(p); err != nil {
		return DoctorReport{
			OK: false,
			Issues: []Issue{{
				Severity: SeverityError,
				Code:     CodeInvalidPlan,
				Message:  err.Error(),
			}},
		}
	}
	checkSSH := opts.CheckSSH
	if checkSSH != nil {
		if !checkSSH(p.SSH.User, p.Bridge.SSHHost, p.BridgeSSHIdentity()) {
			issues = append(
				issues,
				Issue{
					Severity: SeverityError,
					Code:     CodeSSHUnreachable,
					Node:     "bridge",
					Message:  fmt.Sprintf("bridge %s is not reachable over SSH", p.Bridge.SSHHost),
				},
			)
		}
		for _, ex := range p.Exits {
			if !checkSSH(p.SSH.User, ex.SSHHost, p.ExitSSHIdentity(ex)) {
				issues = append(
					issues,
					Issue{
						Severity: SeverityWarning,
						Code:     CodeSSHUnreachable,
						Node:     ex.Name,
						Message: fmt.Sprintf(
							"exit %s (%s) is not reachable over SSH; it will be disabled in bootstrap",
							ex.Name,
							ex.SSHHost,
						),
					},
				)
			}
		}
	}
	if opts.DialTCP != nil {
		if p.Bridge.TunnelPort > 0 {
			if err := opts.DialTCP(ctx, p.Bridge.Address, p.Bridge.TunnelPort); err != nil {
				issues = append(
					issues,
					Issue{
						Severity: SeverityError,
						Code:     CodePortBlocked,
						Node:     "bridge",
						Message:  fmt.Sprintf("bridge VPN port %d is not reachable: %v", p.Bridge.TunnelPort, err),
					},
				)
			}
		}
		if p.Bot.Enabled || (p.Automation != nil && p.Automation.Ingress != nil) {
			if err := opts.DialTCP(ctx, p.Bridge.Address, 80); err != nil {
				issues = append(
					issues,
					Issue{
						Severity: SeverityError,
						Code:     CodePortBlocked,
						Node:     "ingress",
						Message:  fmt.Sprintf("bridge ingress port 80 is not reachable: %v", err),
					},
				)
			}
		}
	}
	if p.Bot.Enabled {
		var tokenErr error
		if p.SecretResolver != nil {
			values, err := ReadPlanSecrets(p)
			tokenErr = err
			if err == nil && strings.TrimSpace(values["TELEGRAM_BOT_TOKEN"]) == "" {
				tokenErr = errors.New("installed_runtime_bot_token_missing")
			}
		} else {
			tokenErr = checkBotToken(p.SecretsEnvFile(), opts.EnvRoot)
		}
		if err := tokenErr; err != nil {
			issues = append(issues, Issue{Severity: SeverityError, Code: CodeMissingBotToken, Node: "bot", Message: err.Error()})
		}
		if opts.LookupHost != nil {
			ips, err := opts.LookupHost(ctx, p.PublicSubscriptionDomain())
			if err != nil || len(ips) == 0 {
				issues = append(
					issues,
					Issue{
						Severity: SeverityError,
						Code:     CodeDNSMismatch,
						Node:     "bot",
						Message:  fmt.Sprintf("bot domain %s has no A/AAAA records", p.PublicSubscriptionDomain()),
					},
				)
			} else if !containsIP(ips, expectedBotHost(p)) {
				issues = append(issues, Issue{Severity: SeverityWarning, Code: CodeDNSMismatch, Node: "bot", Message: fmt.Sprintf("bot domain %s resolves to %s, expected bridge %s", p.PublicSubscriptionDomain(), strings.Join(ips, ","), expectedBotHost(p))})
			}
		}
		if opts.DialTCP != nil {
			if err := opts.DialTCP(ctx, p.Bridge.Address, p.Bot.Port); err != nil {
				issues = append(
					issues,
					Issue{
						Severity: SeverityError,
						Code:     CodePortBlocked,
						Node:     "bot",
						Message:  fmt.Sprintf("bridge bot port %d is not reachable: %v", p.Bot.Port, err),
					},
				)
			}
		}
	}
	return DoctorReport{OK: !hasErrors(issues), Issues: issues}
}

func NetworkDoctorOptions(timeout time.Duration) DoctorOptions {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	resolver := net.DefaultResolver
	return DoctorOptions{
		LookupHost: func(ctx context.Context, host string) ([]string, error) {
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			return resolver.LookupHost(cctx, host)
		},
		DialTCP: func(ctx context.Context, host string, port int) error {
			var d net.Dialer
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			conn, err := d.DialContext(cctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
			if err != nil {
				return err
			}
			_ = conn.Close()
			return nil
		},
	}
}

func RemoteHostDoctor(ctx context.Context) DoctorReport {
	var issues []Issue
	if runtime.GOOS != "linux" {
		issues = append(issues, Issue{Severity: SeverityError, Code: CodeUnsupportedOS, Message: "remote bootstrap requires Linux"})
	}
	switch runtime.GOARCH {
	case "amd64", "arm64":
	default:
		issues = append(
			issues,
			Issue{Severity: SeverityError, Code: CodeUnsupportedArch, Message: "remote bootstrap supports amd64 and arm64"},
		)
	}
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		s := strings.ToLower(string(data))
		if !strings.Contains(s, "debian") && !strings.Contains(s, "ubuntu") {
			issues = append(
				issues,
				Issue{Severity: SeverityWarning, Code: CodeUnsupportedOS, Message: "remote OS is not clearly Debian/Ubuntu"},
			)
		}
	} else {
		issues = append(issues, Issue{Severity: SeverityWarning, Code: CodeUnsupportedOS, Message: "cannot read /etc/os-release"})
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		issues = append(issues, Issue{Severity: SeverityError, Code: CodeMissingSystemd, Message: "systemd is required"})
	}
	opts := NetworkDoctorOptions(3 * time.Second)
	if err := opts.DialTCP(ctx, "github.com", 443); err != nil {
		issues = append(
			issues,
			Issue{Severity: SeverityWarning, Code: CodeGitHubUnreachable, Message: fmt.Sprintf("github.com:443 is not reachable: %v", err)},
		)
	}
	return DoctorReport{OK: !hasErrors(issues), Issues: issues}
}

func checkBotToken(envFile, root string) error {
	if strings.TrimSpace(envFile) == "" {
		envFile = ".env"
	}
	path := envFile
	if root != "" && !strings.HasPrefix(path, "/") {
		path = strings.TrimRight(root, "/") + "/" + path
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("bot token file %s is missing", path)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = stripInlineComment(strings.TrimSpace(line))
		key, val, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "TELEGRAM_BOT_TOKEN" {
			continue
		}
		if strings.TrimSpace(unquote(val)) != "" {
			return nil
		}
	}
	return errors.New("TELEGRAM_BOT_TOKEN is empty or missing")
}

func containsIP(values []string, expected string) bool {
	for _, v := range values {
		if strings.TrimSpace(v) == strings.TrimSpace(expected) {
			return true
		}
	}
	return false
}

func hasErrors(issues []Issue) bool {
	for _, i := range issues {
		if i.Severity == SeverityError {
			return true
		}
	}
	return false
}

func expectedBotHost(p *InstallPlan) string {
	if p.Automation != nil && p.Automation.Ingress != nil && p.Automation.Ingress.ForwardHost != "" {
		return p.Automation.Ingress.ForwardHost
	}
	return p.Bridge.Address
}
