package exits

import (
	"context"
	"log/slog"
	"sync"
)

// Repo is the persistence layer for exit nodes (implemented by db.ExitNodeRepo).
type Repo interface {
	List(ctx context.Context) ([]Node, error)
	ListEnabled(ctx context.Context) ([]Node, error)
	Get(ctx context.Context, id string) (Node, error)
	Add(ctx context.Context, p AddParams) (Node, error)
	Update(ctx context.Context, id string, patch UpdatePatch) (Node, error)
	Delete(ctx context.Context, id string) error
}

// UpdatePatch mirrors db.UpdatePatch without importing db.
type UpdatePatch struct {
	Name     *string
	Address  *string
	Port     *int
	Priority *int
	Enabled  *bool
}

// Manager caches exit nodes and notifies on changes (same pattern as auth.DBManager).
type Manager struct {
	mu       sync.RWMutex
	repo     Repo
	log      *slog.Logger
	cache    []Node
	onChange func([]Node)
}

func NewManager(repo Repo, onChange func([]Node), log *slog.Logger) (*Manager, error) {
	if log == nil {
		log = slog.Default()
	}
	m := &Manager{repo: repo, log: log, onChange: onChange}
	if err := m.refresh(context.Background()); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) refresh(ctx context.Context) error {
	nodes, err := m.repo.List(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.cache = nodes
	m.mu.Unlock()
	return nil
}

func (m *Manager) notify() {
	if m.onChange == nil {
		return
	}
	m.mu.RLock()
	cp := append([]Node(nil), m.cache...)
	m.mu.RUnlock()
	m.onChange(cp)
}

func (m *Manager) List() []Node {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Node, len(m.cache))
	copy(out, m.cache)
	return out
}

func (m *Manager) ListEnabled() []Node {
	return FilterEnabled(m.List())
}

func (m *Manager) Get(id string) (Node, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, n := range m.cache {
		if n.ID == id {
			return n, true
		}
	}
	return Node{}, false
}

func (m *Manager) Add(ctx context.Context, p AddParams) (Node, error) {
	n, err := m.repo.Add(ctx, p)
	if err != nil {
		return Node{}, err
	}
	if err := m.refresh(ctx); err != nil {
		m.log.Warn("exit refresh after Add failed", "err", err)
	}
	m.notify()
	return n, nil
}

func (m *Manager) Update(ctx context.Context, id string, patch UpdatePatch) (Node, error) {
	n, err := m.repo.Update(ctx, id, patch)
	if err != nil {
		return Node{}, err
	}
	if err := m.refresh(ctx); err != nil {
		m.log.Warn("exit refresh after Update failed", "err", err)
	}
	m.notify()
	return n, nil
}

func (m *Manager) Delete(ctx context.Context, id string) error {
	if err := m.repo.Delete(ctx, id); err != nil {
		return err
	}
	if err := m.refresh(ctx); err != nil {
		m.log.Warn("exit refresh after Delete failed", "err", err)
	}
	m.notify()
	return nil
}

func (m *Manager) Reload(ctx context.Context) error {
	if err := m.refresh(ctx); err != nil {
		return err
	}
	m.notify()
	return nil
}
