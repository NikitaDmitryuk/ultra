package exits

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
)

// BootstrapFileName is written by ultra-install on the bridge next to spec.json.
const BootstrapFileName = "exit_nodes.bootstrap.json"

// BootstrapEntry describes one exit row for first-start import into PostgreSQL.
type BootstrapEntry struct {
	Name                 string `json:"name"`
	Address              string `json:"address"`
	Port                 int    `json:"port"`
	TunnelUUID           string `json:"tunnel_uuid"`
	PinnedPeerCertSHA256 string `json:"pinned_peer_cert_sha256,omitempty"`
	Priority             int    `json:"priority"`
	Enabled              *bool  `json:"enabled,omitempty"`
}

// EnabledOrDefault returns true when enabled is omitted from bootstrap JSON.
func (e BootstrapEntry) EnabledOrDefault() bool {
	if e.Enabled == nil {
		return true
	}
	return *e.Enabled
}

// BootstrapEnabledPtr returns a pointer suitable for JSON/bootstrap fields.
func BootstrapEnabledPtr(enabled bool) *bool {
	return &enabled
}

// SetBootstrapCertPin stores the exit cert SHA-256 pin on the matching bootstrap entry.
func SetBootstrapCertPin(entries []BootstrapEntry, address string, port int, pin string) {
	address = strings.TrimSpace(address)
	pin = strings.TrimSpace(pin)
	if address == "" || port <= 0 || pin == "" {
		return
	}
	for i := range entries {
		if strings.TrimSpace(entries[i].Address) == address && entries[i].Port == port {
			entries[i].PinnedPeerCertSHA256 = pin
			return
		}
	}
}

// LoadBootstrapFile reads exit bootstrap entries; missing file returns nil, nil.
func LoadBootstrapFile(path string) ([]BootstrapEntry, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var entries []BootstrapEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("exit bootstrap file is empty")
	}
	return entries, nil
}

// BootstrapTunnelUUID returns tunnel_uuid for address:port from bootstrap entries.
func BootstrapTunnelUUID(entries []BootstrapEntry, address string, port int) string {
	address = strings.TrimSpace(address)
	if address == "" || port <= 0 {
		return ""
	}
	for _, e := range entries {
		if strings.TrimSpace(e.Address) == address && e.Port == port {
			return strings.TrimSpace(e.TunnelUUID)
		}
	}
	return ""
}
