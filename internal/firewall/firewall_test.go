package firewall

import (
	"context"
	"testing"
)

func TestNewManagerOpenCloseNoPanic(t *testing.T) {
	ctx := context.Background()
	m := New()
	if err := m.OpenPort(ctx, 10810); err != nil {
		t.Fatal(err)
	}
	if err := m.ClosePort(ctx, 10810); err != nil {
		t.Fatal(err)
	}
}
