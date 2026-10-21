package main

import (
	"errors"
	"net/url"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func retainedReconcileBotHost(p *installplan.InstallPlan) (string, error) {
	if raw := p.SourceValues["BOT_PUBLIC_URL"]; raw != "" {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" || (u.Port() != "" && u.Port() != "443") {
			return "", errors.New("retained_reconcile_https_origin_required")
		}
		return u.Hostname(), nil
	}
	return p.Bot.Domain, nil
}
