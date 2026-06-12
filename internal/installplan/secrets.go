package installplan

import "strings"

func (p *InstallPlan) SecretsEnvFile() string {
	if p == nil {
		return ""
	}
	if s := strings.TrimSpace(p.Secrets.EnvFile); s != "" {
		return s
	}
	if s := strings.TrimSpace(p.Bot.EnvFile); s != "" {
		return s
	}
	return ".env"
}
