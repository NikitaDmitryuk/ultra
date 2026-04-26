package auth

import (
	"errors"
	"time"
)

// User is a single client identity.
type User struct {
	UUID                 string     `json:"uuid"`
	Name                 string     `json:"name"`
	Note                 string     `json:"note,omitempty"`
	IsActive             bool       `json:"is_active"`
	DisabledAt           *time.Time `json:"disabled_at,omitempty"`
	LeakPolicy           string     `json:"leak_policy,omitempty"`
	LeakMaxConcurrentIPs *int       `json:"leak_max_concurrent_ips,omitempty"`
	LeakMaxUniqueIPs24h  *int       `json:"leak_max_unique_ips_24h,omitempty"`
}

// ErrUserNotFound is returned by RenameUser and RemoveUser when the UUID is unknown.
var ErrUserNotFound = errors.New("auth: user not found")

// ErrEmptyUserName is returned by RenameUser when the new name is empty after trimming.
var ErrEmptyUserName = errors.New("auth: empty user name")
