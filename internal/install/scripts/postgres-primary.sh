#!/bin/bash
# Template processed by fmt.Sprintf — see primarySetupScript in postgres.go for arg order.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -q
apt-get install -y -q postgresql postgresql-contrib

systemctl enable postgresql
systemctl start postgresql

# Wait for PostgreSQL to become ready (up to 30 s).
for i in $(seq 1 30); do
  runuser -s /bin/sh postgres -c "psql -c 'SELECT 1'" >/dev/null 2>&1 && break
  sleep 1
done

# ── Roles ─────────────────────────────────────────────────────────────────────
# CREATE or ALTER (idempotent — ALTER ensures password stays current).
# -s /bin/sh avoids login-shell profile output; quotes: outer double, inner escaped double.
runuser -s /bin/sh postgres -c "psql -c \"CREATE ROLE %s WITH LOGIN PASSWORD '%s';\"" 2>/dev/null || \
  runuser -s /bin/sh postgres -c "psql -c \"ALTER ROLE %s WITH PASSWORD '%s';\""

runuser -s /bin/sh postgres -c "psql -c \"CREATE ROLE %s WITH REPLICATION LOGIN PASSWORD '%s';\"" 2>/dev/null || \
  runuser -s /bin/sh postgres -c "psql -c \"ALTER ROLE %s WITH PASSWORD '%s';\""

# ── Database ──────────────────────────────────────────────────────────────────
runuser -s /bin/sh postgres -c "psql -c \"CREATE DATABASE %s OWNER %s;\"" 2>/dev/null || true
runuser -s /bin/sh postgres -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE %s TO %s;\""

# ── Locate active cluster configuration ───────────────────────────────────────
# --shell /bin/sh avoids login-profile output that would pollute the captured version string.
PG_VER=$(runuser -s /bin/sh postgres -c "psql -Atc 'SHOW server_version_num;'" | tail -1 | cut -c1-2)
PG_CONF_DIR="/etc/postgresql/${PG_VER}/main"
PG_CONF="${PG_CONF_DIR}/postgresql.conf"
PG_HBA="${PG_CONF_DIR}/pg_hba.conf"

# Helper: set or replace a postgresql.conf parameter (idempotent).
setpgconf() {
  local k="$1" v="$2"
  if grep -qE "^#?[[:space:]]*${k}[[:space:]]*=" "$PG_CONF"; then
    sed -i "s|^#*[[:space:]]*${k}[[:space:]]*=.*|${k} = ${v}|" "$PG_CONF"
  else
    echo "${k} = ${v}" >> "$PG_CONF"
  fi
}

# ── Timezone → UTC (ensures DB timestamps match system clock) ─────────────────
setpgconf timezone     "'UTC'"
setpgconf log_timezone "'UTC'"
%s
# ── pg_hba: application access from bridge ───────────────────────────────────
grep -qF '# ultra_app_access' "$PG_HBA" || cat >> "$PG_HBA" << 'HBAEOF'
host    %s    %s    %s/32    scram-sha-256    # ultra_app_access
HBAEOF
%s
systemctl restart postgresql
echo "ultra: PostgreSQL primary ready on port %d."
