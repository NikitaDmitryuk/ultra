package auth

import (
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
