package installplan

import (
	"errors"
	"strings"
)

// DiagnosticConfig uses the canonical parser and exposes only the non-secret
// inputs consumed by the retained read-only operator scripts.
func DiagnosticConfig(path string) (map[string]string, error) {
	values, err := parseLegacyEnvFile(path)
	if err != nil {
		return nil, err
	}
	if _, err = CanonicalValuesToPlan(values); err != nil {
		return nil, err
	}
	keys := []string{"BRIDGE_IP", "BRIDGE_SSH_KEY", "MAIN_EXIT_IP", "MAIN_EXIT_SSH_KEY", "DATABASE_IP", "DATABASE_SSH_KEY", "SSH_USER", "BOT_DOMAIN", "BOT_PORT", "BOT_PUBLIC_URL", "BOT_INGRESS_IP", "REMOTE_DIR", "ULTRA_ROUTING_MODE", "VERIFY_IP_URL", "VERIFY_EXPECTED_EXIT_IP", "VERIFY_PROBE_EXIT_URL", "VERIFY_PROBE_EXIT_PLAIN_URL", "VERIFY_SOCKS_PORT", "VERIFY_SPEC_PATH", "VERIFY_SPLIT_ROUTING", "VERIFY_SSH_KNOWN_HOSTS", "VERIFY_SSH_STRICT_HOST_KEY", "VERIFY_SSH_SUDO", "SSH_STRICT_HOST_KEY"}
	result := map[string]string{}
	for _, key := range keys {
		if value, ok := values[key]; ok {
			if strings.ContainsRune(value, '\x00') {
				return nil, errors.New("diagnostic configuration contains an invalid value")
			}
			result[key] = value
		}
	}
	return result, nil
}
