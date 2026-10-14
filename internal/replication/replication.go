// Package replication maintains asynchronous recovery copies over SSH reverse tunnels.
package replication

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/install"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

// Configurer persists replica installation independently of the relay process.
type Configurer interface {
	ConfigureReplica(context.Context, deployansible.ReplicaRequest) error
	StopReplicaTunnel(context.Context, string) error
}

type Manager struct {
	ensureMu     sync.Mutex
	Config       Config
	DatabaseName string
	Configurer   Configurer
	ctx          context.Context
	Record       func(context.Context, string, string, int64, int64, string) error
}

func New(ctx context.Context, c Config) *Manager {
	return &Manager{Config: c, DatabaseName: "ultra_db", ctx: ctx}
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
	if m.Configurer == nil {
		return errors.New("independent replica executor required")
	}
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
func (m *Manager) Stop(id string) {
	if m.Configurer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = m.Configurer.StopReplicaTunnel(ctx, id)
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
	if m.Configurer == nil {
		m.record(c, id, "error", available, required, "executor_unavailable")
		return "error", errors.New("independent replica executor required")
	}
	request := deployansible.ReplicaRequest{
		ID: id, Host: remote.Host, Identity: remote.Identity, KnownHosts: remote.KnownHosts,
		User: m.Config.User, Password: m.Config.Password, PrimaryPort: m.Config.Port,
		Architecture: expected, RequiredBytes: required, Connections: connections,
		Workers: workers, Prepared: prepared, Locks: locks, Senders: senders,
	}
	if major != 16 {
		return "incompatible", errors.New("PostgreSQL 16 replica required")
	}
	if e = request.ValidatePolicy(); e != nil {
		return "error", e
	}
	if e = m.Configurer.ConfigureReplica(c, request); e != nil {
		m.record(c, id, "error", available, required, "bootstrap_failed")
		return "error", e
	}
	m.record(c, id, "syncing", available, required, "")
	return "syncing", nil
}

// RefreshHeartbeat is called on the application pool independently of activity.
// It must never use the replication role or the maintenance postgres database.
func RefreshHeartbeat(ctx context.Context, database interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}) error {
	_, err := database.Exec(ctx, `INSERT INTO recovery_heartbeat(singleton, observed_at) VALUES(true, now()) ON CONFLICT(singleton) DO UPDATE SET observed_at=EXCLUDED.observed_at`)
	return err
}

func heartbeatFresh(raw string, now time.Time) bool {
	seconds, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil || seconds <= 0 {
		return false
	}
	age := now.Sub(time.Unix(int64(seconds), 0))
	return age >= -30*time.Second && age <= 5*time.Minute
}

func (m *Manager) Check(ctx context.Context, id string, remote install.Remote) error {
	if !regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(m.DatabaseName) {
		m.record(ctx, id, "error", 0, 0, "heartbeat_database_invalid")
		return errors.New("heartbeat database not configured")
	}
	output, e := remote.Run(ctx, fmt.Sprintf(`set -eu
if [ ! -f /var/lib/ultra-postgres-replica/data/PG_VERSION ]; then echo not_configured; exit 0; fi
free=$(df -Pk /var/lib | awk 'NR==2 {print $4}')
if [ "$free" -lt 1048576 ]; then systemctl stop ultra-postgres-replica; echo insufficient_space; exit 0; fi
runuser -u postgres -- psql -p 5433 -At -d postgres -c "SELECT CASE WHEN pg_is_in_recovery() THEN 'replica' ELSE 'unexpected_primary' END"
runuser -u postgres -- psql -p 5433 -XAtq -v ON_ERROR_STOP=1 -d '%s' -c "SELECT extract(epoch from observed_at) FROM recovery_heartbeat WHERE singleton"
`, m.DatabaseName))
	if e != nil {
		m.record(ctx, id, "error", 0, 0, "health_check_failed")
		return e
	}
	fields := strings.Fields(string(output))
	state := "error"
	if len(fields) > 0 {
		state = fields[0]
	}
	heartbeat := ""
	if len(fields) > 1 {
		heartbeat = fields[1]
	}
	if state == "replica" {
		conn, e := m.primary(ctx)
		if e != nil {
			m.record(ctx, id, "error", 0, 0, "primary_check_failed")
			return e
		}
		defer conn.Close(ctx) //nolint:errcheck
		var lag int64
		var streaming bool
		e = conn.QueryRow(ctx, `SELECT state='streaming',COALESCE(pg_wal_lsn_diff(pg_current_wal_lsn(),replay_lsn),9223372036854775807)::bigint FROM pg_stat_replication WHERE application_name=$1`, "ultra_"+strings.ReplaceAll(id, "-", "")).Scan(&streaming, &lag)
		if e != nil || !streaming {
			state = "disconnected"
		} else if lag > 16*1024*1024 || !heartbeatFresh(heartbeat, time.Now()) {
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
