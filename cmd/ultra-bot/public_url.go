package main

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// The public origin may use a different port from the local TLS listener.
func resolvePublicURL(override, domain, port string, dev bool) (string, error) {
	if override != "" {
		u, err := url.Parse(override)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" ||
			(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(override, "#") {
			return "", errors.New("public-url must be an HTTPS origin without credentials, path, query or fragment")
		}
		u.Path = "/"
		return u.String(), nil
	}
	if domain == "" {
		return "", nil
	}
	scheme := "https"
	if dev {
		scheme = "http"
	}
	if port == "443" || (dev && port == "80") {
		return fmt.Sprintf("%s://%s/", scheme, domain), nil
	}
	return fmt.Sprintf("%s://%s:%s/", scheme, domain, port), nil
}
