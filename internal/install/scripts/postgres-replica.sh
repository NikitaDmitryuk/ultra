#!/bin/bash
# Template processed by fmt.Sprintf — see replicaSetupScript in postgres.go for arg order.
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
