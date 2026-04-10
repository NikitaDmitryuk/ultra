package install

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// PostgresConfig holds parameters for a managed PostgreSQL installation.
type PostgresConfig struct {
	DBName       string // database name (default: ultra_db)
	DBUser       string // application role name (default: ultra)
	DBPassword   string // generated if empty (hex, no special chars)
	ReplUser     string // replication role name (default: ultra_repl)
	ReplPassword string // generated if empty (hex, no special chars)
	Port         int    // PostgreSQL port (default: 5432)
	BridgeHost   string // source IP for pg_hba app access (127.0.0.1 when DB is co-located with bridge)
	ReplicaHost  string // source IP for pg_hba replication access; empty = no streaming replica
}

// Defaults fills zero fields with sensible values and generates random hex passwords.
func (c *PostgresConfig) Defaults() error {
	if c.DBName == "" {
		c.DBName = "ultra_db"
	}
	if c.DBUser == "" {
		c.DBUser = "ultra"
	}
	if c.ReplUser == "" {
		c.ReplUser = "ultra_repl"
	}
	if c.Port == 0 {
		c.Port = 5432
	}
	if c.DBPassword == "" {
		b := make([]byte, 24)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		c.DBPassword = hex.EncodeToString(b)
	}
	if c.ReplPassword == "" {
		b := make([]byte, 24)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		c.ReplPassword = hex.EncodeToString(b)
	}
	return nil
}

// DSN returns the libpq connection string for the bridge to use.
func (c *PostgresConfig) DSN(host string) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		c.DBUser, c.DBPassword, host, c.Port, c.DBName,
	)
}

// SetupPrimaryPostgres installs and configures PostgreSQL on the primary host over SSH.
// The operation is idempotent: running it a second time updates passwords and HBA without harm.
func SetupPrimaryPostgres(sshUser, host, identity string, cfg PostgresConfig) error {
	return RunSSH(sshUser, host, identity, primarySetupScript(cfg))
}

// SetupReplicaPostgres installs PostgreSQL on the replica host and bootstraps
// streaming replication from primaryHost via pg_basebackup.
// Must be called after SetupPrimaryPostgres (primary must be running and accessible).
func SetupReplicaPostgres(sshUser, host, identity string, cfg PostgresConfig, primaryHost string) error {
	return RunSSH(sshUser, host, identity, replicaSetupScript(cfg, primaryHost))
}

// primarySetupScript returns the bash script that installs and configures the primary PostgreSQL node.
// Passwords are hex strings so they are safe to embed literally in SQL single-quoted literals.
func primarySetupScript(cfg PostgresConfig) string {
	// WAL streaming config — only needed when a replica is expected.
	walSection := ""
	if cfg.ReplicaHost != "" {
		walSection = `
setpgconf wal_level        replica
setpgconf max_wal_senders  10
setpgconf wal_keep_size    256
setpgconf listen_addresses "'*'"
`
	}

	// pg_hba entry for replication role — only when replica host is known.
	replHBASection := ""
	if cfg.ReplicaHost != "" {
		replHBASection = fmt.Sprintf(`
# ── Replication access from replica ──────────────────────────────────────────
grep -qF '# ultra_repl_access' "$PG_HBA" || cat >> "$PG_HBA" << 'HBAEOF'
host    replication    %s    %s/32    scram-sha-256    # ultra_repl_access
HBAEOF
`,
			cfg.ReplUser, cfg.ReplicaHost,
		)
	}

	// Passwords are hex — no single quotes, no backslashes; safe to interpolate in SQL literals.
	// runuser switches to postgres without requiring sudo/password — it works from root directly.
	return fmt.Sprintf(`#!/bin/bash
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
`,
		// app role: CREATE
		cfg.DBUser, cfg.DBPassword,
		// app role: ALTER (idempotent)
		cfg.DBUser, cfg.DBPassword,
		// repl role: CREATE
		cfg.ReplUser, cfg.ReplPassword,
		// repl role: ALTER (idempotent)
		cfg.ReplUser, cfg.ReplPassword,
		// database
		cfg.DBName, cfg.DBUser,
		// grant
		cfg.DBName, cfg.DBUser,
		// WAL section (may be empty)
		walSection,
		// pg_hba app access: dbname, user, bridgeHost
		cfg.DBName, cfg.DBUser, cfg.BridgeHost,
		// replication HBA section (may be empty)
		replHBASection,
		// port in final echo
		cfg.Port,
	)
}

// replicaSetupScript returns the bash script that bootstraps a streaming replica via pg_basebackup.
func replicaSetupScript(cfg PostgresConfig, primaryHost string) string {
	// Passwords are hex — safe to embed in PGPASSWORD and connstring.
	// runuser -l resets the environment, so PGPASSWORD must be set inside the -c command.
	// We write a temporary helper script owned by postgres to avoid quoting issues with
	// shell variable expansion inside the runuser -c argument.
	return fmt.Sprintf(`#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8

apt-get update -q
apt-get install -y -q postgresql postgresql-contrib

# Detect installed PostgreSQL major version
PG_VER=$(pg_config --version | grep -oP '\d+' | head -1)
DATA_DIR="/var/lib/postgresql/${PG_VER}/main"
PG_CONF_DIR="/etc/postgresql/${PG_VER}/main"

# Stop PostgreSQL and drop the default cluster so pg_basebackup can populate the data dir.
systemctl stop postgresql || true
pg_dropcluster --stop "${PG_VER}" main 2>/dev/null || true
rm -rf "${DATA_DIR}"
mkdir -p "${DATA_DIR}"
chown postgres:postgres "${DATA_DIR}"
chmod 700 "${DATA_DIR}"

# Write a helper script that pg_basebackup runs as the postgres user.
# Avoids quoting/expansion issues when passing PGPASSWORD + args via runuser -c.
cat > /tmp/ultra_pg_basebackup.sh << 'SCRIPTEOF'
#!/bin/bash
set -euo pipefail
export PGPASSWORD='REPLPASS_PLACEHOLDER'
pg_basebackup \
  -h 'PRIMARY_HOST_PLACEHOLDER' \
  -p PRIMARY_PORT_PLACEHOLDER \
  -U 'REPLUSER_PLACEHOLDER' \
  -D "$1" \
  --wal-method=stream \
  --write-recovery-conf \
  --progress \
  --checkpoint=fast
SCRIPTEOF

# Substitute placeholders (passwords are hex — no shell-special chars).
sed -i "s/REPLPASS_PLACEHOLDER/%s/" /tmp/ultra_pg_basebackup.sh
sed -i "s/PRIMARY_HOST_PLACEHOLDER/%s/" /tmp/ultra_pg_basebackup.sh
sed -i "s/PRIMARY_PORT_PLACEHOLDER/%d/" /tmp/ultra_pg_basebackup.sh
sed -i "s/REPLUSER_PLACEHOLDER/%s/" /tmp/ultra_pg_basebackup.sh

chown postgres:postgres /tmp/ultra_pg_basebackup.sh
chmod 700 /tmp/ultra_pg_basebackup.sh

# Bootstrap replica data directory from primary.
# runuser switches from root to postgres without requiring sudo/password.
runuser -s /bin/sh postgres -c "/tmp/ultra_pg_basebackup.sh '${DATA_DIR}'"
rm -f /tmp/ultra_pg_basebackup.sh

chown -R postgres:postgres "${DATA_DIR}"
chmod 700 "${DATA_DIR}"

# Restore cluster config directory if pg_dropcluster removed it.
mkdir -p "${PG_CONF_DIR}"
chown postgres:postgres "${PG_CONF_DIR}"

# Minimal pg_hba: allow local connections for health checks.
if [ ! -f "${PG_CONF_DIR}/pg_hba.conf" ]; then
  cat > "${PG_CONF_DIR}/pg_hba.conf" << 'HBAEOF'
local   all   postgres   peer
local   all   all        peer
host    all   all        127.0.0.1/32   scram-sha-256
HBAEOF
fi

systemctl enable postgresql
systemctl start postgresql
echo "ultra: PostgreSQL replica ready (hot standby)."
`,
		cfg.ReplPassword,
		primaryHost,
		cfg.Port,
		cfg.ReplUser,
	)
}

// FormatDBEnvLine returns a shell environment variable line for /etc/ultra-relay/environment.
func FormatDBEnvLine(dsn string) string {
	return "ULTRA_RELAY_DB_DSN=" + dsn + "\n"
}
