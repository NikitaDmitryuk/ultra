package exits

import (
	"context"
	"errors"
	"testing"
)

type deleteRefreshRepo struct {
	nodes    []Node
	failList bool
}

func (r *deleteRefreshRepo) List(context.Context) ([]Node, error) {
	if r.failList {
		return nil, errors.New("database unavailable after commit")
	}
	return append([]Node(nil), r.nodes...), nil
}
func (r *deleteRefreshRepo) ListEnabled(c context.Context) ([]Node, error) { return r.List(c) }
func (r *deleteRefreshRepo) Get(context.Context, string) (Node, error)     { return Node{}, nil }
func (r *deleteRefreshRepo) Add(context.Context, AddParams) (Node, error)  { return Node{}, nil }
func (r *deleteRefreshRepo) Update(context.Context, string, UpdatePatch) (Node, error) {
	return Node{}, nil
}
func (r *deleteRefreshRepo) Delete(_ context.Context, id string) error {
	for i, n := range r.nodes {
		if n.ID == id {
			r.nodes = append(r.nodes[:i], r.nodes[i+1:]...)
			break
		}
	}
	r.failList = true
	return nil
}
func TestCommittedDeleteFencesCachedNodeWhenDatabaseRefreshFails(t *testing.T) {
	repo := &deleteRefreshRepo{nodes: []Node{{ID: "nl", Enabled: true}, {ID: "us", Enabled: true}}}
	var notified []Node
	manager, err := NewManager(repo, func(nodes []Node) { notified = nodes }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.Delete(context.Background(), "us"); err != nil {
		t.Fatal(err)
	}
	if _, ok := manager.Get("us"); ok {
		t.Fatal("deleted node remained in cache")
	}
	if len(notified) != 1 || notified[0].ID != "nl" {
		t.Fatalf("callback published stale exit %v", notified)
	}
}
