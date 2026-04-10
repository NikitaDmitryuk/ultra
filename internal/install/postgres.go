package install

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
)

//go:embed scripts/postgres-primary.sh
var postgresPrimaryScriptTmpl string

//go:embed scripts/postgres-replica.sh
var postgresReplicaScriptTmpl string

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

	return fmt.Sprintf(postgresPrimaryScriptTmpl,
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
	return fmt.Sprintf(postgresReplicaScriptTmpl,
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
