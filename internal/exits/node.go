package exits

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Node is a bridge upstream exit (stored in PostgreSQL on the bridge).
type Node struct {
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	Address              string    `json:"address"`
	Port                 int       `json:"port"`
	TunnelUUID           string    `json:"tunnel_uuid"`
	PinnedPeerCertSHA256 string    `json:"pinned_peer_cert_sha256,omitempty"`
	CountryCode          string    `json:"country_code,omitempty"`
	CountryName          string    `json:"country_name,omitempty"`
	City                 string    `json:"city,omitempty"`
	DisplayName          string    `json:"display_name,omitempty"`
	Priority             int       `json:"priority"`
	Enabled              bool      `json:"enabled"`
	CreatedAt            time.Time `json:"created_at,omitempty"`
	UpdatedAt            time.Time `json:"updated_at,omitempty"`
}

// OutboundTag returns the Xray outbound tag for this exit node.
func OutboundTag(id string) string {
	return "to-exit-" + id
}

// DialAddr returns host:port for TCP probes.
func (n Node) DialAddr() string {
	return fmt.Sprintf("%s:%d", n.Address, n.Port)
}

// LocationLabel returns the best user-facing label for this exit location.
func (n Node) LocationLabel() string {
	if s := strings.TrimSpace(n.DisplayName); s != "" {
		return s
	}
	city := strings.TrimSpace(n.City)
	country := strings.TrimSpace(n.CountryName)
	switch {
	case city != "" && country != "":
		return city + ", " + country
	case city != "":
		return city
	case country != "":
		return country
	default:
		return n.Name
	}
}

// Health holds probe results for one exit node.
type Health struct {
	ID                string `json:"id"`
	Reachable         bool   `json:"reachable"`
	InternetOK        bool   `json:"internet_ok"`
	TunnelLatencyMS   int64  `json:"tunnel_latency_ms,omitempty"`
	InternetLatencyMS int64  `json:"internet_latency_ms,omitempty"`
	Active            bool   `json:"active,omitempty"`
}

// SelectActive picks the enabled exit with the lowest priority among reachable nodes.
// If none are reachable, returns the enabled node with lowest priority (degraded).
func SelectActive(nodes []Node, reachable map[string]bool) (Node, bool) {
	enabled := FilterEnabled(nodes)
	if len(enabled) == 0 {
		return Node{}, false
	}
	sort.Slice(enabled, func(i, j int) bool {
		if enabled[i].Priority != enabled[j].Priority {
			return enabled[i].Priority < enabled[j].Priority
		}
		return enabled[i].ID < enabled[j].ID
	})
	for _, n := range enabled {
		if reachable[n.ID] {
			return n, true
		}
	}
	return enabled[0], false
}

// FilterEnabled returns only enabled nodes preserving order.
func FilterEnabled(nodes []Node) []Node {
	var out []Node
	for _, n := range nodes {
		if n.Enabled {
			out = append(out, n)
		}
	}
	return out
}
