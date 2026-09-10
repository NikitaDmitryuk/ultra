package rtc

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// ServiceConfig is optional. Private content is never required when disabled.
type ServiceConfig struct {
	Enabled           bool   `json:"enabled"`
	ContentFile       string `json:"content_file,omitempty"`
	Socket            string `json:"socket,omitempty"`
	GatewayPort       int    `json:"gateway_port,omitempty"`
	EncryptionKeyFile string `json:"encryption_key_file,omitempty"`
}
type Link struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}
type RoomRule struct {
	Host        string `json:"host"`
	PathPattern string `json:"path_pattern"`
	Provider    string `json:"provider"`
}
type Guide struct {
	Steps          []string   `json:"steps"`
	Warning        string     `json:"warning"`
	Links          []Link     `json:"links"`
	ImportTemplate string     `json:"import_template"`
	Rules          []RoomRule `json:"-"`
}
type PrivateContent struct {
	Guide        Guide      `json:"guide"`
	RoomRules    []RoomRule `json:"room_rules"`
	ProbeURL     string     `json:"probe_url"`
	BootstrapDNS string     `json:"bootstrap_dns"`
	MaxAccesses  int        `json:"max_accesses"`
}

func LoadContent(path string) (*PrivateContent, error) {
	fail := errors.New("rtc: private configuration unavailable")
	st, e := os.Stat(path)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&7 != 0 {
		return nil, fail
	}
	b, e := os.ReadFile(path)
	if e != nil || len(b) > 65536 {
		return nil, fail
	}
	var c PrivateContent
	if json.Unmarshal(b, &c) != nil || len(c.Guide.Steps) == 0 || len(c.RoomRules) == 0 {
		return nil, fail
	}
	if c.MaxAccesses == 0 {
		c.MaxAccesses = 10
	}
	if c.MaxAccesses < 1 || c.MaxAccesses > 10 {
		return nil, fail
	}
	if !safeHTTPS(c.ProbeURL) {
		return nil, fail
	}
	for _, l := range c.Guide.Links {
		if !safeHTTPS(l.URL) {
			return nil, fail
		}
	}
	host, port, e := net.SplitHostPort(c.BootstrapDNS)
	if e != nil || net.ParseIP(host) == nil || port != "53" {
		return nil, fail
	}
	template, e := url.Parse(strings.ReplaceAll(c.Guide.ImportTemplate, "{url}", "example"))
	if e != nil || template.Host == "" || template.Scheme == "javascript" || template.Scheme == "data" || template.Scheme == "file" || template.Scheme == "http" {
		return nil, fail
	}
	if strings.Count(c.Guide.ImportTemplate, "{url}") != 1 {
		return nil, fail
	}
	for _, r := range c.RoomRules {
		if r.Host == "" || (r.Provider != "telemost" && r.Provider != "wbstream") {
			return nil, fail
		}
		re, e := regexp.Compile(r.PathPattern)
		if e != nil || re.NumSubexp() != 1 {
			return nil, fail
		}
	}
	return &c, nil
}
func safeHTTPS(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Port() == ""
}
func (c *PrivateContent) ParseRoom(raw string) (provider, room string, err error) {
	fail := errors.New("invalid_room")
	if len(raw) > 2048 {
		return "", "", fail
	}
	u, e := url.Parse(strings.TrimSpace(raw))
	if e != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return "", "", fail
	}
	for _, r := range c.RoomRules {
		if strings.EqualFold(u.Host, r.Host) {
			re := regexp.MustCompile(r.PathPattern)
			m := re.FindStringSubmatch(u.Path)
			if len(m) == 2 && m[0] == u.Path && regexp.MustCompile(`^[a-zA-Z0-9_-]{1,160}$`).MatchString(m[1]) {
				return r.Provider, m[1], nil
			}
		}
	}
	return "", "", fail
}
