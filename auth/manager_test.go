package auth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestManagerReloadAndAdd(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "users.json")
	if err := os.WriteFile(p, []byte(`[{"uuid":"2784871e-d8a9-4e1f-b831-3d86aa8653ee","name":"a"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls int
	m, err := NewManager(p, time.Hour, func([]User) { calls++ })
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if calls < 1 {
		t.Fatalf("expected initial callback, got %d", calls)
	}
	u, ok := m.Lookup("2784871e-d8a9-4e1f-b831-3d86aa8653ee")
	if !ok || u.Name != "a" {
		t.Fatal(u, ok)
	}
	if _, err := m.AddUser("bob"); err != nil {
		t.Fatal(err)
	}
	if len(m.List()) != 2 {
		t.Fatal(m.List())
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 50 {
		t.Fatalf("expected persisted file: %s", data)
	}
}

func TestManagerRenameRemove(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "users.json")
	seed := `[{"uuid":"2784871e-d8a9-4e1f-b831-3d86aa8653ee","name":"a"}]`
	if err := os.WriteFile(p, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(p, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	if _, err := m.RenameUser("00000000-0000-0000-0000-000000000000", "x"); err == nil {
		t.Fatal("expected ErrUserNotFound")
	} else if !errors.Is(err, ErrUserNotFound) {
		t.Fatal(err)
	}
	if _, err := m.RenameUser("2784871e-d8a9-4e1f-b831-3d86aa8653ee", " "); !errors.Is(err, ErrEmptyUserName) {
		t.Fatal("expected ErrEmptyUserName", err)
	}

	u, err := m.RenameUser("2784871e-d8a9-4e1f-b831-3d86aa8653ee", "alice")
	if err != nil || u.Name != "alice" {
		t.Fatal(u, err)
	}
	if got, _ := m.Lookup("2784871e-d8a9-4e1f-b831-3d86aa8653ee"); got.Name != "alice" {
		t.Fatal(got)
	}

	if err := m.RemoveUser("2784871e-d8a9-4e1f-b831-3d86aa8653ee"); err != nil {
		t.Fatal(err)
	}
	if len(m.List()) != 0 {
		t.Fatal(m.List())
	}
	if err := m.RemoveUser("2784871e-d8a9-4e1f-b831-3d86aa8653ee"); !errors.Is(err, ErrUserNotFound) {
		t.Fatal("expected ErrUserNotFound on second delete", err)
	}
}
