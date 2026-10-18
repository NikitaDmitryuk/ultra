package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

func (s *Server) databaseRoutes() {
	s.mux.HandleFunc("GET /v1/database", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if s.DatabaseStatus == nil {
			http.Error(w, "database observation unavailable", http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		status := s.DatabaseStatus(ctx)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status)
	})
}
