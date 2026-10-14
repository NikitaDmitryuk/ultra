package adminapi

import (
	"encoding/base64"
	"net/url"
	"sort"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

const (
	automaticProfileName        = "🌐 Автоматически"
	automaticProfileDescription = "Автовыбор доступного выхода"
	countryProfileDescription   = "Приоритет страны с резервом"
)

// Subscription choices are intentionally smaller than the compatible /client export.
// Existing credentials and transports remain valid; reads never create credentials.
func subscriptionURIs(spec *config.Spec, user auth.User, nodes []exits.Node, health map[string]exits.Health, transport string) ([]string, error) {
	uris := []string{}
	add := func(u auth.User, name, description, selectedTransport string) error {
		exp, err := config.BuildSubscriptionExport(spec, u, selectedTransport)
		if err != nil {
			return err
		}
		uri, err := url.Parse(exp.VLESSURI)
		if err != nil {
			return err
		}
		uri.Fragment = name + "?serverDescription=" + base64.StdEncoding.EncodeToString([]byte(description))
		uris = append(uris, uri.String())
		return nil
	}
	if err := eachSubscriptionProfile(user, nodes, health, func(u auth.User, name, description string) error {
		return add(u, name, description, transport)
	}); err != nil {
		return nil, err
	}

	return uris, nil
}

func subscriptionHapp(spec *config.Spec, user auth.User, nodes []exits.Node, health map[string]exits.Health) ([]map[string]any, error) {
	profiles := []map[string]any{}
	err := eachSubscriptionProfile(user, nodes, health, func(u auth.User, name, description string) error {
		profile, err := config.BuildHappProfile(spec, u, name)
		if err == nil {
			profile["meta"] = map[string]any{"serverDescription": description}
			profiles = append(profiles, profile)
		}
		return err
	})
	return profiles, err
}

func eachSubscriptionProfile(user auth.User, nodes []exits.Node, _ map[string]exits.Health, add func(auth.User, string, string) error) error {
	if err := add(user, automaticProfileName, automaticProfileDescription); err != nil {
		return err
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
		name := subscriptionCountryName(n)
		// Publication is stable across health changes: a country credential prefers
		// this exit, while runtime selection handles failover and quota enforcement.
		if code == "" || name == "" || !n.Enabled || seen[code] {
			continue
		}
		for _, route := range user.Routes {
			if !route.Published || route.ExitID == nil || *route.ExitID != n.ID {
				continue
			}
			alias := user
			alias.UUID = route.UUID
			if err := add(alias, subscriptionCountryProfileName(n), countryProfileDescription); err != nil {
				return err
			}
			seen[code] = true
			break
		}
	}
	return nil
}

func subscriptionCountryProfileName(n exits.Node) string {
	name := subscriptionCountryName(n)
	flag := countryFlag(n.CountryCode)
	if flag == "" {
		return name
	}
	return flag + " " + name
}

func countryFlag(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return ""
	}
	region, err := language.ParseRegion(code)
	if err != nil || !region.IsCountry() {
		return ""
	}
	code = region.Canonicalize().String()
	if len(code) != 2 {
		return ""
	}
	return string(rune(0x1F1E6+int(code[0]-'A'))) + string(rune(0x1F1E6+int(code[1]-'A')))
}

func subscriptionCountryName(n exits.Node) string {
	code := strings.ToUpper(strings.TrimSpace(n.CountryCode))
	if code == "US" {
		return "США"
	}
	name := strings.TrimSpace(n.CountryName)
	if region, err := language.ParseRegion(code); err == nil && len(code) == 2 {
		name = display.Regions(language.Russian).Name(region)
	}
	return name
}
