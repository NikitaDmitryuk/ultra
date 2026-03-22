package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/uuid"
)

// ErrUserNotFound is returned by RenameUser and RemoveUser when the UUID is unknown.
var ErrUserNotFound = errors.New("auth: user not found")

// ErrEmptyUserName is returned by RenameUser when the new name is empty after trimming.
var ErrEmptyUserName = errors.New("auth: empty user name")

// User is a single client identity stored in users.json.
type User struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

// Manager is a thread-safe store backed by a JSON file. It reloads the file
// periodically and can persist updates atomically (for the admin API).
type Manager struct {
	mu sync.RWMutex

	path     string
	interval time.Duration

	byID map[string]User
	list []User

	onChange func([]User)

	stop chan struct{}
	done chan struct{}
}

// NewManager loads path immediately, then re-reads the file every interval.
// onChange is invoked after each successful load or Save that changed content.
func NewManager(path string, interval time.Duration, onChange func([]User)) (*Manager, error) {
	return newManager(path, interval, onChange, true)
}

// NewManagerDeferredFirstNotify loads users.json like NewManager but skips the first onChange
// callback so the caller can start other listeners (e.g. Admin API) before the first heavy reload.
func NewManagerDeferredFirstNotify(path string, interval time.Duration, onChange func([]User)) (*Manager, error) {
	return newManager(path, interval, onChange, false)
}

func newManager(path string, interval time.Duration, onChange func([]User), invokeInitialOnChange bool) (*Manager, error) {
	if path == "" {
		return nil, errors.New("auth: empty users file path")
	}
	if interval <= 0 {
		interval = 60 * time.Second
	}
	m := &Manager{
		path:     path,
		interval: interval,
		byID:     make(map[string]User),
		onChange: onChange,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	if err := m.reloadFromDiskInvoke(invokeInitialOnChange); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	go m.loop()
	return m, nil
}

func (m *Manager) loop() {
	defer close(m.done)
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			_ = m.reloadFromDisk()
		}
	}
}

// Close stops the background reload loop.
func (m *Manager) Close() {
	close(m.stop)
	<-m.done
}

func (m *Manager) reloadFromDisk() error {
	return m.reloadFromDiskInvoke(true)
}

func (m *Manager) reloadFromDiskInvoke(invokeOnChange bool) error {
	data, err := os.ReadFile(m.path)
	if err != nil {
		return err
	}
	var users []User
	if err := json.Unmarshal(data, &users); err != nil {
		return err
	}
	return m.applySnapshot(users, false, invokeOnChange)
}

func (m *Manager) applySnapshot(users []User, forceNotify bool, invokeOnChange bool) error {
	byID := make(map[string]User, len(users))
	for _, u := range users {
		if u.UUID == "" {
			continue
		}
		byID[u.UUID] = u
	}
	encoded, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}

	m.mu.Lock()
	changed := forceNotify || !bytes.Equal(encoded, m.lastEncodedLocked())
	m.byID = byID
	m.list = append([]User(nil), users...)
	m.mu.Unlock()

	if changed && m.onChange != nil && (forceNotify || invokeOnChange) {
		m.onChange(append([]User(nil), users...))
	}
	return nil
}

func (m *Manager) lastEncodedLocked() []byte {
	if len(m.list) == 0 {
		return nil
	}
	b, _ := json.MarshalIndent(m.list, "", "  ")
	return b
}

// Lookup returns a user by protocol client id (UUID).
func (m *Manager) Lookup(id string) (User, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.byID[id]
	return u, ok
}

// List returns a copy of all users.
func (m *Manager) List() []User {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]User, len(m.list))
	copy(out, m.list)
	return out
}

// AddUser appends a user with a fresh UUID, writes users.json atomically, and notifies.
func (m *Manager) AddUser(name string) (User, error) {
	id := uuid.New()
	u := User{UUID: (&id).String(), Name: name}

	m.mu.Lock()
	next := append(append([]User(nil), m.list...), u)
	m.mu.Unlock()

	if err := m.saveUsers(next); err != nil {
		return User{}, err
	}
	if err := m.applySnapshot(next, true, true); err != nil {
		return User{}, err
	}
	return u, nil
}

// RenameUser updates the display name for an existing UUID.
func (m *Manager) RenameUser(id, name string) (User, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return User{}, ErrEmptyUserName
	}
	m.mu.Lock()
	next := make([]User, len(m.list))
	copy(next, m.list)
	var out User
	found := false
	for i := range next {
		if next[i].UUID == id {
			next[i].Name = name
			out = next[i]
			found = true
			break
		}
	}
	m.mu.Unlock()
	if !found {
		return User{}, ErrUserNotFound
	}
	if err := m.saveUsers(next); err != nil {
		return User{}, err
	}
	if err := m.applySnapshot(next, true, true); err != nil {
		return User{}, err
	}
	return out, nil
}

// RemoveUser deletes a user by UUID and rewrites users.json.
func (m *Manager) RemoveUser(id string) error {
	if id == "" {
		return ErrUserNotFound
	}
	m.mu.Lock()
	next := make([]User, 0, len(m.list))
	found := false
	for _, u := range m.list {
		if u.UUID == id {
			found = true
			continue
		}
		next = append(next, u)
	}
	m.mu.Unlock()
	if !found {
		return ErrUserNotFound
	}
	if err := m.saveUsers(next); err != nil {
		return err
	}
	return m.applySnapshot(next, true, true)
}

func (m *Manager) saveUsers(users []User) error {
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}

// Path returns the backing file path.
func (m *Manager) Path() string { return m.path }
