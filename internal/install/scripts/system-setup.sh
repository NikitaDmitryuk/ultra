#!/bin/bash
set -euo pipefail
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

# ── Journald size cap (prevents multi-GB log accumulation) ───────────────────
JCONF=/etc/systemd/journald.conf
if ! grep -q '^SystemMaxUse=' "$JCONF" 2>/dev/null; then
  echo 'SystemMaxUse=100M' >> "$JCONF"
fi
if ! grep -q '^RuntimeMaxUse=' "$JCONF" 2>/dev/null; then
  echo 'RuntimeMaxUse=50M' >> "$JCONF"
fi
journalctl --vacuum-size=100M >/dev/null 2>&1 || true
systemctl kill --kill-who=main --signal=SIGHUP systemd-journald 2>/dev/null || true
echo "ultra: journald capped at 100M."
