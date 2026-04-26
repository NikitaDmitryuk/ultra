package auth

import (
	"context"
	"log/slog"
	"sync"
)

// DBUserRepo is the subset of db.UserRepo used by DBManager.
// Declared here to avoid an import cycle (auth → db → auth).
type DBUserRepo interface {
	Add(ctx context.Context, name string) (User, error)
	Rename(ctx context.Context, id, name string) (User, error)
	Remove(ctx context.Context, id string) error
	Enable(ctx context.Context, id string) error
	RotateUUID(ctx context.Context, id string) (string, error)
	List(ctx context.Context) ([]User, error)
	ListAll(ctx context.Context) ([]User, error)
	Lookup(ctx context.Context, id string) (User, bool, error)
}

// DBManager is a UserManager backed by PostgreSQL (via DBUserRepo).
// It maintains an in-memory cache so List/Lookup are non-blocking reads.
// The cache is refreshed after every write; Xray is notified via onChange.
type DBManager struct {
	mu   sync.RWMutex
	repo DBUserRepo
	log  *slog.Logger

	cacheActive []User
	cacheAll    []User
	byID        map[string]User

	onChange func([]User)
}

// Ensure DBManager satisfies UserManager at compile time.
var _ UserManager = (*DBManager)(nil)

// NewDBManager creates a DBManager, pre-loads the user list from the DB, and returns.
// onChange is called after any mutation with the updated user list (same contract as Manager).
func NewDBManager(repo DBUserRepo, onChange func([]User), log *slog.Logger) (*DBManager, error) {
	if log == nil {
		log = slog.Default()
	}
	m := &DBManager{
		repo:     repo,
		log:      log,
		byID:     make(map[string]User),
		onChange: onChange,
	}
	if err := m.refresh(context.Background()); err != nil {
		return nil, err
	}
	return m, nil
}

// refresh reloads the full user list from the DB into the in-memory cache.
func (m *DBManager) refresh(ctx context.Context) error {
	users, err := m.repo.ListAll(ctx)
	if err != nil {
		return err
	}
	byID := make(map[string]User, len(users))
	active := make([]User, 0, len(users))
	for _, u := range users {
		byID[u.UUID] = u
		if u.IsActive {
			active = append(active, u)
		}
	}
	m.mu.Lock()
	m.cacheAll = users
	m.cacheActive = active
	m.byID = byID
	m.mu.Unlock()
	return nil
}

func (m *DBManager) notify() {
	if m.onChange == nil {
		return
	}
	m.mu.RLock()
	cp := append([]User(nil), m.cacheActive...)
	m.mu.RUnlock()
	m.onChange(cp)
}

// AddUser inserts a new user and triggers an Xray reload.
func (m *DBManager) AddUser(name string) (User, error) {
	u, err := m.repo.Add(context.Background(), name)
	if err != nil {
		return User{}, err
	}
	if err := m.refresh(context.Background()); err != nil {
		m.log.Warn("db refresh after AddUser failed", "err", err)
	}
	m.notify()
	return u, nil
}

// RenameUser updates the display name and triggers an Xray reload.
func (m *DBManager) RenameUser(id, name string) (User, error) {
	u, err := m.repo.Rename(context.Background(), id, name)
	if err != nil {
		return User{}, err
	}
	if err := m.refresh(context.Background()); err != nil {
		m.log.Warn("db refresh after RenameUser failed", "err", err)
	}
	m.notify()
	return u, nil
}

// RemoveUser soft-deletes a user and triggers an Xray reload.
func (m *DBManager) RemoveUser(id string) error {
	if err := m.repo.Remove(context.Background(), id); err != nil {
		return err
	}
	if err := m.refresh(context.Background()); err != nil {
		m.log.Warn("db refresh after RemoveUser failed", "err", err)
	}
	m.notify()
	return nil
}

// EnableUser restores a disabled user and triggers an Xray reload.
func (m *DBManager) EnableUser(id string) error {
	if err := m.repo.Enable(context.Background(), id); err != nil {
		return err
	}
	if err := m.refresh(context.Background()); err != nil {
		m.log.Warn("db refresh after EnableUser failed", "err", err)
	}
	m.notify()
	return nil
}

// RotateUUID reissues a user's UUID and triggers an Xray reload.
func (m *DBManager) RotateUUID(id string) (string, error) {
	newUUID, err := m.repo.RotateUUID(context.Background(), id)
	if err != nil {
		return "", err
	}
	if err := m.refresh(context.Background()); err != nil {
		m.log.Warn("db refresh after RotateUUID failed", "err", err)
	}
	m.notify()
	return newUUID, nil
}

// List returns a copy of the cached user list (non-blocking).
func (m *DBManager) List() []User {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]User, len(m.cacheActive))
	copy(out, m.cacheActive)
	return out
}

// ListAll returns both active and disabled users.
func (m *DBManager) ListAll() []User {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]User, len(m.cacheAll))
	copy(out, m.cacheAll)
	return out
}

// Lookup returns a single user from the cache (non-blocking).
func (m *DBManager) Lookup(id string) (User, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.byID[id]
	return u, ok
}

// Close is a no-op for DBManager (no background goroutine to stop).
func (m *DBManager) Close() {}
