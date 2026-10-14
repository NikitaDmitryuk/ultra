package adminapi

import "net/http"

func (s *Server) requireTopologyReady(w http.ResponseWriter, r *http.Request) bool {
	if s.TopologyReady != nil {
		if err := s.TopologyReady(r.Context()); err != nil {
			http.Error(w, "infrastructure operation in progress or controller unavailable", http.StatusServiceUnavailable)
			return false
		}
	}
	return true
}

// Drain confirms a durable controller reservation and waits for every topology
// mutation which started before it. It does not pause traffic or change data.
// Inspection must follow this barrier, never precede the reservation.
func (s *Server) handleDeploymentDrain(w http.ResponseWriter, r *http.Request) {
	s.topologyMu.Lock()
	defer s.topologyMu.Unlock()
	if s.TopologyFrozen == nil {
		http.Error(w, "deployment gate unavailable", http.StatusServiceUnavailable)
		return
	}
	frozen, err := s.TopologyFrozen(r.Context())
	if err != nil || !frozen {
		http.Error(w, "confirmed deployment gate required", http.StatusConflict)
		return
	}
	if s.Cloud != nil {
		unlock, err := s.Cloud.Store.Lock(r.Context())
		if err != nil {
			http.Error(w, "topology drain unavailable", http.StatusServiceUnavailable)
			return
		}
		defer unlock()
		frozen, err = s.TopologyFrozen(r.Context())
		if err != nil || !frozen {
			http.Error(w, "deployment gate changed", http.StatusConflict)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"verified":true}`))
}
