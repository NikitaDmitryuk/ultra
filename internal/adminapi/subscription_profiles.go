package adminapi

import (
	"net/url"
	"sort"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

// Subscription choices are intentionally smaller than the compatible /client export.
// Existing credentials and transports remain valid; reads never create credentials.
func subscriptionURIs(spec *config.Spec, user auth.User, nodes []exits.Node, health map[string]exits.Health) ([]string, error) {
	uris := []string{}
	add := func(u auth.User, name string) error {
		exp, err := config.BuildSubscriptionExport(spec, u)
		if err != nil {
			return err
		}
		uri, err := url.Parse(exp.VLESSURI)
		if err != nil {
			return err
		}
		uri.Fragment = name
		uris = append(uris, uri.String())
		return nil
	}
	if err := add(user, "Автоматически"); err != nil {
		return nil, err
	}
	nodes = append([]exits.Node(nil), nodes...)
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Priority != nodes[j].Priority {
			return nodes[i].Priority < nodes[j].Priority
		}
		return nodes[i].ID < nodes[j].ID
	})
	seen := map[string]bool{}
	for _, n := range nodes {
		code := strings.ToUpper(strings.TrimSpace(n.CountryCode))
		name := strings.TrimSpace(n.CountryName)
		if region, err := language.ParseRegion(code); err == nil && len(code) == 2 {
			name = display.Regions(language.Russian).Name(region)
		}
		if code == "" || name == "" || !n.Enabled || !health[n.ID].Eligible || seen[code] {
			continue
		}
		for _, route := range user.Routes {
			if !route.Published || route.ExitID == nil || *route.ExitID != n.ID {
				continue
			}
			alias := user
			alias.UUID = route.UUID
			if err := add(alias, name); err != nil {
				return nil, err
			}
			seen[code] = true
			break
		}
	}
	return uris, nil
}
