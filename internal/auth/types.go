package auth

import (
	"errors"
	"time"
)

// LegacySocksUserUUID is the synthetic admin-list id for the global spec.socks5 inbound.
// It is not stored in PostgreSQL.
const LegacySocksUserUUID = "_legacy_socks"

// User is a single client identity.
type RouteCredential struct {
	UUID       string
	LocationID string
	Name       string
	ExitID     *string
	Published  bool
}

type User struct {
	ExitExclusionReasons map[string]string `json:"-"`
	FallbackExitID       string            `json:"-"`
	ExcludedExitIDs      []string          `json:"-"`
	Routes               []RouteCredential `json:"-"`
	UUID                 string            `json:"uuid"`
	Name                 string            `json:"name"`
	Kind                 string            `json:"kind"`
	IsActive             bool              `json:"is_active"`
	DisabledAt           *time.Time        `json:"disabled_at,omitempty"`
	// PreferredExitID retains the legacy account preference; only fixed credentials use it.
	PreferredExitID *string `json:"preferred_exit_id,omitempty"`
	// FixedExit marks a location credential, including an unpublished or deleted location.
	FixedExit bool `json:"-"`
	// EffectiveExitID is computed at config-build time and is not persisted.
	EffectiveExitID string `json:"-"`
	// Historical SOCKS5 fields are retained for archived database rows only.
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

// ErrInvalidUserKind is returned when kind is not VLESS.
var ErrInvalidUserKind = errors.New("auth: invalid user kind")

// ExpandRoutes is used only by configuration generation; aliases are not separate account records.
func ExpandRoutes(users []User) []User {
	out := make([]User, 0, len(users))
	for _, u := range users {
		out = append(out, u)
		for _, route := range u.Routes {
			alias := u
			alias.UUID = route.UUID
			alias.Routes = nil
			alias.PreferredExitID = route.ExitID
			alias.FixedExit = true
			out = append(out, alias)
		}
	}
	return out
}
