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

// FormatDBEnvLine returns a shell environment variable line for /etc/ultra-relay/environment.
func FormatDBEnvLine(dsn string) string {
	return "ULTRA_RELAY_DB_DSN=" + dsn + "\n"
}
