package install

// SystemSetupScript returns a bash script that configures locale and timezone on a remote node.
//
// What it does:
//   - Sets system timezone to UTC (idempotent via timedatectl or /etc/localtime symlink).
//   - Generates en_US.UTF-8 locale and writes it to /etc/default/locale so that all
//     subsequent bash -lc sessions export LC_ALL/LANG automatically.
//
// Without this, apt-get/nginx/perl print "Setting locale failed" warnings during every
// package install because the server ships without a generated locale.
//
// Idempotent — safe to run on an already-configured node.
func SystemSetupScript() string {
	return `set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# ── Timezone → UTC ────────────────────────────────────────────────────────────
if command -v timedatectl >/dev/null 2>&1; then
  timedatectl set-timezone UTC
else
  ln -sf /usr/share/zoneinfo/UTC /etc/localtime
  echo UTC > /etc/timezone
fi

# ── Locale → en_US.UTF-8 ─────────────────────────────────────────────────────
# Suppress "perl: warning: Setting locale failed" during package installation.
# bash -lc sessions source /etc/default/locale, so update-locale persists across
# all subsequent SSH calls in this install run.
if ! locale -a 2>/dev/null | grep -qF 'en_US.utf8'; then
  apt-get install -y -q locales
  locale-gen en_US.UTF-8
fi
update-locale LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8 LANGUAGE=en_US:en
echo "ultra: system timezone=UTC locale=en_US.UTF-8 configured."
`
}

// SetupSystem runs SystemSetupScript on the remote host over SSH.
func SetupSystem(sshUser, host, identity string) error {
	return RunSSH(sshUser, host, identity, SystemSetupScript())
}
