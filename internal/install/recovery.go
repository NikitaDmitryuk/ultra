package install

import (
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// EnableRecoveryNode authorizes the bridge worker to maintain an isolated replica.
// This remains callable by the local installer; no cloud API is required.
func EnableRecoveryNode(user, primary, target, identity string) error {
	if primary == target {
		return errors.New("replica must differ from primary")
	}
	output, err := RunSSHOutput(user, primary, identity, `set -eu
install -d -m 700 /var/lib/ultra-relay/automation
if [ ! -f /var/lib/ultra-relay/automation/id_ed25519 ]; then ssh-keygen -q -t ed25519 -N '' -f /var/lib/ultra-relay/automation/id_ed25519 >/dev/null; fi
cat /var/lib/ultra-relay/automation/id_ed25519.pub
`)
	if err != nil {
		return errors.New("automation public key unavailable")
	}
	parts := strings.Fields(string(output))
	if len(parts) < 2 || parts[0] != "ssh-ed25519" {
		return errors.New("invalid automation public key")
	}
	if _, err = base64.StdEncoding.DecodeString(parts[1]); err != nil {
		return errors.New("invalid automation public key")
	}
	public := parts[0] + " " + parts[1]
	if err = RunSSH(user, target, identity, fmt.Sprintf(`set -eu
install -d -m 700 /root/.ssh
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
grep -qF -- '%s' /root/.ssh/authorized_keys || printf '%%s\n' '%s ultra-recovery-worker' >> /root/.ssh/authorized_keys
`, public, public)); err != nil {
		return errors.New("replica SSH authorization failed")
	}
	return RunSSH(user, primary, identity, recoveryPrimaryScript)
}

// This script operates on a co-located primary and preserves existing application credentials.
//
//go:embed scripts/recovery-primary.sh
var recoveryPrimaryScript string
