package install

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/url"
	"strconv"
)

// PostgresConfig holds parameters for a managed PostgreSQL installation.
type PostgresConfig struct {
	DBName     string // database name (default: ultra_db)
	DBUser     string // application role name (default: ultra)
	DBPassword string // generated if empty (hex, no special chars)
	Port       int    // PostgreSQL port (default: 5432)
}

// Defaults fills zero fields with sensible values and generates random hex passwords.
func (c *PostgresConfig) Defaults() error {
	if c.DBName == "" {
		c.DBName = "ultra_db"
	}
	if c.DBUser == "" {
		c.DBUser = "ultra"
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
	return nil
}

// DSN returns the libpq connection string for the bridge to use.
func (c *PostgresConfig) DSN(host string) string {
	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(c.DBUser, c.DBPassword),
		Host:   net.JoinHostPort(host, strconv.Itoa(c.Port)),
		Path:   "/" + c.DBName,
	}
	u.RawQuery = "sslmode=disable"
	return u.String()
}

// FormatDBEnvLine returns a shell environment variable line for /etc/ultra-relay/environment.
func FormatDBEnvLine(dsn string) string {
	return "ULTRA_RELAY_DB_DSN=" + dsn + "\n"
}
