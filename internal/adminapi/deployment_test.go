package adminapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDeploymentDrainWaitsForOldMutationAndRequiresConfirmedGate(t *testing.T) {
	s := &Server{TopologyFrozen: func(context.Context) (bool, error) { return true, nil }}
	s.topologyMu.Lock()
	done := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		s.handleDeploymentDrain(w, httptest.NewRequest(http.MethodPost, "/v1/deployment/drain", nil))
		done <- w.Code
	}()
	select {
	case <-done:
		t.Fatal("drain ignored in-flight mutation")
	case <-time.After(20 * time.Millisecond):
	}
	s.topologyMu.Unlock()
	if status := <-done; status != http.StatusOK {
		t.Fatal(status)
	}
	for _, f := range []func(context.Context) (bool, error){func(context.Context) (bool, error) { return false, nil }, func(context.Context) (bool, error) { return false, errors.New("unavailable") }} {
		s.TopologyFrozen = f
		w := httptest.NewRecorder()
		s.handleDeploymentDrain(w, httptest.NewRequest(http.MethodPost, "/v1/deployment/drain", nil))
		if w.Code == http.StatusOK {
			t.Fatal("unconfirmed gate drained")
		}
	}
}
func TestTopologyGateRejectsDirectExitMutationsBeforeChangingState(t *testing.T) {
	s := &Server{TopologyReady: func(context.Context) error { return errors.New("busy") }}
	for _, handler := range []http.HandlerFunc{s.handlePostExit, s.handlePatchExit, s.handleDeleteExit} {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest(http.MethodPost, "/v1/exits", nil))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatal(w.Code)
		}
	}
}
