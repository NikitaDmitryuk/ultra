package install

import (
	"fmt"
	"strings"
)

// RemoteCertSHA256 reads a PEM certificate on host via SSH and returns its SHA-256 fingerprint
// in Xray pinnedPeerCertSha256 format (lowercase hex, no colons).
func RemoteCertSHA256(user, host, identity, certPath string) (string, error) {
	script := fmt.Sprintf(
		`openssl x509 -noout -fingerprint -sha256 -in %q | sed 's/SHA256 Fingerprint=//i' | tr -d ':' | tr '[:upper:]' '[:lower:]'`,
		certPath,
	)
	out, err := RunSSHOutput(user, host, identity, script)
	if err != nil {
		return "", fmt.Errorf("remote cert fingerprint (%s): %w", host, err)
	}
	pin := strings.TrimSpace(string(out))
	if pin == "" {
		return "", fmt.Errorf("remote cert fingerprint (%s): empty output", host)
	}
	return pin, nil
}
