package auth

import "errors"

// User is a single client identity.
type User struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

// ErrUserNotFound is returned by RenameUser and RemoveUser when the UUID is unknown.
var ErrUserNotFound = errors.New("auth: user not found")

// ErrEmptyUserName is returned by RenameUser when the new name is empty after trimming.
var ErrEmptyUserName = errors.New("auth: empty user name")
