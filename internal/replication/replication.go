// Package replication maintains asynchronous recovery copies over SSH reverse tunnels.
package replication

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/install"
	"github.com/jackc/pgx/v5"
)

const GiB int64 = 1 << 30

func RequiredFreeBytes(clusterBytes int64) int64 {
	required := 2*clusterBytes + 2*GiB
	if required < 5*GiB {
		return 5 * GiB
	}
	return required
}

type Config struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Port     int    `json:"port"`
}

func Load(path string) (Config, error) {
	var c Config
	info, e := os.Stat(path)
	if e != nil || info.Mode().Perm()&0007 != 0 {
		return c, errors.New("replication credentials unavailable")
	}
	data, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	if json.Unmarshal(data, &c) != nil || !regexp.MustCompile(`^[a-z_][a-z0-9_]*$`).MatchString(c.User) || !regexp.MustCompile(`^[a-f0-9]{48,128}$`).MatchString(c.Password) || c.Port <= 0 || c.Port > 65535 {
		return Config{}, errors.New("replication configuration invalid")
	}
	return c, nil
}

type Manager struct {
	ensureMu sync.Mutex
	Config   Config
	ctx      context.Context
	mu       sync.Mutex
	tunnels  map[string]context.CancelFunc
	Record   func(context.Context, string, string, int64, int64, string) error
}

func New(ctx context.Context, c Config) *Manager {
	return &Manager{Config: c, ctx: ctx, tunnels: map[string]context.CancelFunc{}}
}
func (m *Manager) primary(ctx context.Context) (*pgx.Conn, error) {
	cfg, e := pgx.ParseConfig("host=127.0.0.1 sslmode=disable dbname=postgres")
	if e != nil {
		return nil, e
	}
	cfg.User = m.Config.User
	cfg.Password = m.Config.Password
	cfg.Port = uint16(m.Config.Port)
	return pgx.ConnectConfig(ctx, cfg)
}
func (m *Manager) Ready(ctx context.Context) error {
	conn, e := m.primary(ctx)
	if e != nil {
		return errors.New("primary replication access unavailable")
	}
	defer conn.Close(ctx) //nolint:errcheck
	var level string
	var slots int
	var cap int64
	if e = conn.QueryRow(ctx, `SELECT current_setting('wal_level'),current_setting('max_replication_slots')::int,CASE WHEN current_setting('max_slot_wal_keep_size')='-1' THEN -1 ELSE pg_size_bytes(current_setting('max_slot_wal_keep_size')) END`).Scan(&level, &slots, &cap); e != nil {
		return e
	}
	if level != "replica" && level != "logical" || slots < 3 || cap <= 0 || cap > GiB {
		return errors.New("primary needs bounded WAL replication configuration")
	}

	var externalTablespaces bool
	if e = conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_tablespace WHERE spcname NOT IN ('pg_default','pg_global'))`).Scan(&externalTablespaces); e != nil {
		return e
	}
	if externalTablespaces {
		return errors.New("external tablespaces require an explicit recovery layout")
	}
	return nil
}
func (m *Manager) startTunnel(id string, remote install.Remote) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tunnels[id]; ok {
		return
	}
	ctx, cancel := context.WithCancel(m.ctx)
	m.tunnels[id] = cancel
	go func() {
		for ctx.Err() == nil {
			// GatewayPorts=yes can override an explicit loopback bind on the SSH server.
			check, cancel := context.WithTimeout(ctx, 8*time.Second)
			_, safe := remote.Run(check, `test "$(sshd -T | awk '$1=="gatewayports" {print $2}')" = no || test "$(sshd -T | awk '$1=="gatewayports" {print $2}')" = clientspecified`)
			cancel()
			if safe == nil {
				_ = remote.ReverseTunnel(ctx, m.Config.Port)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()
}
func (m *Manager) Stop(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cancel, ok := m.tunnels[id]; ok {
		cancel()
		delete(m.tunnels, id)
	}
}
func (m *Manager) record(ctx context.Context, id, state string, free, required int64, detail string) {
	if m.Record != nil {
		_ = m.Record(ctx, id, state, free, required, detail)
	}
}

// Ensure creates only our own cluster. Existing PostgreSQL directories are never dropped or overwritten.
func (m *Manager) Ensure(ctx context.Context, id string, remote install.Remote) (string, error) {
	m.ensureMu.Lock()
	defer m.ensureMu.Unlock()
	if !regexp.MustCompile(`^[a-f0-9-]{36}$`).MatchString(id) {
		return "error", errors.New("invalid replica id")
	}
	c, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if e := m.Ready(c); e != nil {
		return "error", e
	}
	conn, e := m.primary(c)
	if e != nil {
		return "error", errors.New("primary unavailable")
	}
	defer conn.Close(c) //nolint:errcheck
	var bytes int64
	var major, connections, workers, prepared, locks, senders int
	e = conn.QueryRow(c, `SELECT (SELECT COALESCE(SUM(pg_database_size(oid)),0)::bigint FROM pg_database WHERE datallowconn),current_setting('server_version_num')::int/10000,current_setting('max_connections')::int,current_setting('max_worker_processes')::int,current_setting('max_prepared_transactions')::int,current_setting('max_locks_per_transaction')::int,current_setting('max_wal_senders')::int`).Scan(&bytes, &major, &connections, &workers, &prepared, &locks, &senders)
	if e != nil {
		return "error", errors.New("primary sizing unavailable")
	}
	arch, e := remote.Run(c, "uname -m")
	if e != nil {
		return "error", e
	}
	expected := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]
	if expected == "" || strings.TrimSpace(string(arch)) != expected {
		m.record(c, id, "incompatible", 0, 0, "architecture_mismatch")
		return "incompatible", nil
	}
	output, e := remote.Run(c, `df -Pk /var/lib | awk 'NR==2 {print $4}'`)
	if e != nil {
		return "error", e
	}
	available, e := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64)
	if e != nil {
		return "error", e
	}
	available *= 1024
	required := RequiredFreeBytes(bytes)
	if available < required {
		m.record(c, id, "insufficient_space", available, required, "")
		return "insufficient_space", nil
	}
	m.record(c, id, "syncing", available, required, "")
	m.startTunnel(id, remote)
	slot := "ultra_" + strings.ReplaceAll(id, "-", "")
	var exists bool
	if e = conn.QueryRow(c, `SELECT EXISTS(SELECT 1 FROM pg_replication_slots WHERE slot_name=$1)`, slot).Scan(&exists); e != nil {
		return "error", e
	}
	if !exists {
		if _, e = conn.Exec(c, `SELECT pg_create_physical_replication_slot($1)`, slot); e != nil {
			return "error", errors.New("replication slot creation failed")
		}
	}
	// Variables below are validated integers, a generated hex password, and a generated slot identifier.
	script := fmt.Sprintf(`set -eu
export DEBIAN_FRONTEND=noninteractive
MAJOR=%d
ROOT=/var/lib/ultra-postgres-replica
CONF=/etc/ultra-postgres-replica
BIN=/usr/lib/postgresql/$MAJOR/bin
if [ ! -x "$BIN/pg_basebackup" ]; then apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq postgresql-$MAJOR >/dev/null 2>&1; fi
install -d -m 700 -o postgres -g postgres "$ROOT" "$CONF"
if [ -e "$ROOT/data" ] && [ ! -f "$ROOT/managed-by-ultra" ]; then exit 42; fi
if [ -f "$ROOT/data/PG_VERSION" ] && [ "$(cat "$ROOT/data/PG_VERSION")" != "$MAJOR" ]; then exit 43; fi
if [ -f "$ROOT/data/PG_VERSION" ] && [ ! -f "$ROOT/data/standby.signal" ]; then exit 44; fi
printf '127.0.0.1:15432:*:%s:%s\n' > "$CONF/pgpass"
chown postgres:postgres "$CONF/pgpass"; chmod 600 "$CONF/pgpass"
if [ ! -f "$ROOT/data/PG_VERSION" ]; then
 STAGING=$(mktemp -d "$ROOT/seed.XXXXXX")
 chown postgres:postgres "$STAGING"
 trap 'rm -rf -- "$STAGING"' EXIT
 ready=0
 for attempt in $(seq 1 30); do if "$BIN/pg_isready" -h 127.0.0.1 -p 15432 >/dev/null 2>&1; then ready=1; break; fi; sleep 1; done
 [ "$ready" = 1 ]
 runuser -u postgres -- env PGPASSFILE="$CONF/pgpass" "$BIN/pg_basebackup" -h 127.0.0.1 -p 15432 -U %s -D "$STAGING" --wal-method=stream --slot=%s --checkpoint=spread >/dev/null 2>&1
 [ ! -e "$ROOT/data" ]
 touch "$STAGING/standby.signal"
 touch "$ROOT/managed-by-ultra"
 mv "$STAGING" "$ROOT/data"
 trap - EXIT
fi
: > "$ROOT/data/postgresql.auto.conf"
touch "$ROOT/data/standby.signal"
cat > "$CONF/postgresql.conf" <<'PGCONF'
listen_addresses = '127.0.0.1'
port = 5433
shared_buffers = '64MB'
hot_standby = on
max_connections = %d
max_worker_processes = %d
max_prepared_transactions = %d
max_locks_per_transaction = %d
max_wal_senders = %d
hba_file = '/etc/ultra-postgres-replica/pg_hba.conf'
primary_conninfo = 'host=127.0.0.1 port=15432 user=%s passfile=/etc/ultra-postgres-replica/pgpass application_name=%s sslmode=disable'
primary_slot_name = '%s'
PGCONF
printf 'local all postgres peer\nhost all all 127.0.0.1/32 reject\n' > "$CONF/pg_hba.conf"
chown -R postgres:postgres "$CONF"
cat > /etc/systemd/system/ultra-postgres-replica.service <<UNIT
[Unit]
Description=Ultra PostgreSQL recovery replica
After=network-online.target
[Service]
User=postgres
ExecStart=$BIN/postgres -D $ROOT/data -c config_file=$CONF/postgresql.conf
Restart=on-failure
RestartSec=10
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable ultra-postgres-replica >/dev/null 2>&1
systemctl restart ultra-postgres-replica
`, major, m.Config.User, m.Config.Password, m.Config.User, slot, connections, workers, prepared, locks, senders, m.Config.User, slot, slot)
	if _, e = remote.Run(c, script); e != nil {
		m.record(c, id, "error", available, required, "bootstrap_failed")
		return "error", e
	}
	m.record(c, id, "syncing", available, required, "")
	return "syncing", nil
}
func (m *Manager) Check(ctx context.Context, id string, remote install.Remote) error {
	m.startTunnel(id, remote)
	output, e := remote.Run(ctx, `set -eu
if [ ! -f /var/lib/ultra-postgres-replica/data/PG_VERSION ]; then echo not_configured; exit 0; fi
free=$(df -Pk /var/lib | awk 'NR==2 {print $4}')
if [ "$free" -lt 1048576 ]; then systemctl stop ultra-postgres-replica; echo insufficient_space; exit 0; fi
runuser -u postgres -- psql -p 5433 -At -d postgres -c "SELECT CASE WHEN pg_is_in_recovery() THEN 'replica' ELSE 'unexpected_primary' END"
`)
	if e != nil {
		m.record(ctx, id, "error", 0, 0, "health_check_failed")
		return e
	}
	state := strings.TrimSpace(string(output))
	if state == "replica" {
		conn, e := m.primary(ctx)
		if e != nil {
			return e
		}
		defer conn.Close(ctx) //nolint:errcheck
		var lag int64
		var streaming bool
		e = conn.QueryRow(ctx, `SELECT state='streaming',COALESCE(pg_wal_lsn_diff(pg_current_wal_lsn(),replay_lsn),9223372036854775807)::bigint FROM pg_stat_replication WHERE application_name=$1`, "ultra_"+strings.ReplaceAll(id, "-", "")).Scan(&streaming, &lag)
		if e != nil || !streaming {
			state = "disconnected"
		} else if lag > 16*1024*1024 {
			state = "lagging"
		} else {
			state = "streaming"
		}
	}
	if state == "unexpected_primary" || state == "insufficient_space" {
		m.Stop(id)
	}
	m.record(ctx, id, state, 0, 0, "")
	return nil
}
func (m *Manager) RemoveSlot(ctx context.Context, id string) error {
	m.Stop(id)
	conn, e := m.primary(ctx)
	if e != nil {
		return e
	}
	defer conn.Close(ctx) //nolint:errcheck
	slot := "ultra_" + strings.ReplaceAll(id, "-", "")
	for attempt := 0; attempt < 5; attempt++ {
		var exists, active bool
		if e = conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_replication_slots WHERE slot_name=$1),EXISTS(SELECT 1 FROM pg_replication_slots WHERE slot_name=$1 AND active)`, slot).Scan(&exists, &active); e != nil {
			return e
		}
		if !exists {
			return nil
		}
		if !active {
			_, e = conn.Exec(ctx, `SELECT pg_drop_replication_slot($1)`, slot)
			return e
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return errors.New("replication slot still active")
}
