package auth

import (
	"errors"
	"time"
)

// LegacySocksUserUUID is the synthetic admin-list id for the global spec.socks5 inbound.
// It is not stored in PostgreSQL.
const LegacySocksUserUUID = "_legacy_socks"

// User is a single client identity.
type User struct {
	UUID       string     `json:"uuid"`
	Name       string     `json:"name"`
	Kind       string     `json:"kind"`
	IsActive   bool       `json:"is_active"`
	DisabledAt *time.Time `json:"disabled_at,omitempty"`
	// SOCKS5 client credentials (kind=socks5); never exposed in list JSON — use /client.
	SocksUsername string `json:"-"`
	SocksPassword string `json:"-"`
	SocksPort     *int   `json:"-"`
	// Leak fields are still loaded from DB for internal use but never exposed in
	// Admin / Mini App JSON: thresholds are global (see internal/bot/leak.go).
	LeakPolicy           string `json:"-"`
	LeakMaxConcurrentIPs *int   `json:"-"`
	LeakMaxUniqueIPs24h  *int   `json:"-"`
}

// ErrUserNotFound is returned by RenameUser and RemoveUser when the UUID is unknown.
var ErrUserNotFound = errors.New("auth: user not found")

// ErrEmptyUserName is returned by RenameUser when the new name is empty after trimming.
var ErrEmptyUserName = errors.New("auth: empty user name")

// ErrUnsupportedForKind is returned when an operation does not apply to the user's kind.
var ErrUnsupportedForKind = errors.New("auth: unsupported for this user kind")

// ErrInvalidUserKind is returned when kind is not vless or socks5.
var ErrInvalidUserKind = errors.New("auth: invalid user kind")

// ErrSocksPortsExhausted is returned when no TCP port is free in the configured SOCKS5 client range.
var ErrSocksPortsExhausted = errors.New("auth: no free port in socks5 port range")
