package exits

import (
	"testing"
)

func TestSelectActiveFailover(t *testing.T) {
	nodes := []Node{
		{ID: "a", Priority: 100, Enabled: true},
		{ID: "b", Priority: 200, Enabled: true},
	}
	reachable := map[string]bool{"a": true, "b": true}
	active, ok := SelectActive(nodes, reachable)
	if !ok || active.ID != "a" {
		t.Fatalf("expected primary a, got %+v ok=%v", active, ok)
	}
	reachable = map[string]bool{"b": true}
	active, ok = SelectActive(nodes, reachable)
	if !ok || active.ID != "b" {
		t.Fatalf("expected backup b, got %+v", active)
	}
}

func TestSelectActiveDegraded(t *testing.T) {
	nodes := []Node{
		{ID: "a", Priority: 100, Enabled: true},
		{ID: "b", Priority: 200, Enabled: true},
	}
	active, ok := SelectActive(nodes, map[string]bool{})
	if ok {
		t.Fatal("expected degraded selection")
	}
	if active.ID != "a" {
		t.Fatalf("expected lowest-priority enabled node, got %q", active.ID)
	}
}

func TestOutboundTag(t *testing.T) {
	if OutboundTag("abc") != "to-exit-abc" {
		t.Fatal(OutboundTag("abc"))
	}
}
