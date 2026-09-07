package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
)

func (s *Server) cloudRoutes() {
	s.mux.HandleFunc("GET /v1/cloud/replicas", func(w http.ResponseWriter, r *http.Request) {
		if s.ReplicationStatus == nil {
			http.Error(w, "replication unavailable", http.StatusServiceUnavailable)
			return
		}
		v, e := s.ReplicationStatus(r.Context())
		cloudResult(w, v, e)
	})
	s.mux.HandleFunc("GET /v1/cloud/catalog", s.cloudCatalog)
	s.mux.HandleFunc("GET /v1/cloud/operations", s.cloudOperations)
	s.mux.HandleFunc("GET /v1/cloud/operations/{id}/events", func(w http.ResponseWriter, r *http.Request) {
		if !s.requireCloud(w) {
			return
		}
		v, e := s.Cloud.Store.Events(r.Context(), r.PathValue("id"))
		cloudResult(w, v, e)
	})
	s.mux.HandleFunc("POST /v1/cloud/offers", s.cloudOffer)
	s.mux.HandleFunc("POST /v1/cloud/offers/{id}/confirm", s.cloudConfirm)
	s.mux.HandleFunc("POST /v1/cloud/operations/{id}/action", s.cloudAction)
}
func (s *Server) requireCloud(w http.ResponseWriter) bool {
	w.Header().Set("Cache-Control", "no-store")
	if s.Cloud == nil {
		http.Error(w, "Vultr automation unavailable", http.StatusServiceUnavailable)
		return false
	}
	return true
}
func cloudResult(w http.ResponseWriter, value any, e error) {
	if e != nil {
		status := 503
		switch {
		case errors.Is(e, cloud.ErrLimit), errors.Is(e, cloud.ErrConflict), errors.Is(e, cloud.ErrPriceChanged):
			status = 409
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		code := cloud.ErrorCode(e)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "message": cloud.ErrorMessage(code)})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
func (s *Server) cloudCatalog(w http.ResponseWriter, r *http.Request) {
	if !s.requireCloud(w) {
		return
	}
	regions, plans, e := s.Cloud.Catalog(r.Context())
	cloudResult(w, map[string]any{"regions": regions, "plans": plans, "max_servers": 2, "max_monthly_cost": 5}, e)
}
func (s *Server) cloudOperations(w http.ResponseWriter, r *http.Request) {
	if !s.requireCloud(w) {
		return
	}
	ops, e := s.Cloud.Store.List(r.Context())
	cloudResult(w, ops, e)
}
func (s *Server) cloudOffer(w http.ResponseWriter, r *http.Request) {
	if !s.requireCloud(w) {
		return
	}
	var body struct {
		Actor     int64  `json:"actor"`
		Region    string `json:"region"`
		Plan      string `json:"plan"`
		ReplaceID string `json:"replace_id"`
	}
	if !s.decodeAdminJSON(w, r, &body) {
		return
	}
	offer, e := s.Cloud.Quote(r.Context(), body.Actor, body.Region, body.Plan, body.ReplaceID)
	cloudResult(w, offer, e)
}
func (s *Server) cloudConfirm(w http.ResponseWriter, r *http.Request) {
	if !s.requireCloud(w) {
		return
	}
	var body struct {
		Actor int64 `json:"actor"`
	}
	if !s.decodeAdminJSON(w, r, &body) {
		return
	}
	op, e := s.Cloud.Confirm(r.Context(), body.Actor, r.PathValue("id"))
	cloudResult(w, op, e)
}
func (s *Server) cloudAction(w http.ResponseWriter, r *http.Request) {
	if !s.requireCloud(w) {
		return
	}
	var body struct {
		Action string `json:"action"`
		Actor  int64  `json:"actor"`
	}
	if !s.decodeAdminJSON(w, r, &body) {
		return
	}
	e := s.Cloud.Action(r.Context(), body.Actor, r.PathValue("id"), body.Action)
	cloudResult(w, map[string]bool{"accepted": e == nil}, e)
}
