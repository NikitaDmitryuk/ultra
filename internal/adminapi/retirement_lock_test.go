package adminapi

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCloudTopologyLeaseWaitsForAdminMutation(t *testing.T) {
	s := &Server{}
	s.topologyMu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		unlock, err := s.LockTopologyMutation(ctx)
		if unlock != nil {
			unlock()
		}
		done <- err
	}()
	<-started
	cancel()
	s.topologyMu.Unlock()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled waiter entered topology: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("topology waiter deadlocked")
	}
	unlock, err := s.LockTopologyMutation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	unlock()
}
