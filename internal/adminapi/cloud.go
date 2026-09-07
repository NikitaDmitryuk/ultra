package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/db"
)

func (s *Server) cloudRoutes() {
	s.mux.HandleFunc("GET /v1/cloud/quotas", func(w http.ResponseWriter, r *http.Request) {
		if !s.requireMembers(w) {
			return
		}
		budgets, e := s.Members.Repo.Budgets(r.Context())
		if e != nil {
			memberJSON(w, nil, e)
			return
		}
		type node struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Enabled bool   `json:"enabled"`
			Ready   bool   `json:"ready"`
			Primary bool   `json:"primary"`
		}
		nodes := []node{}
		if s.exits != nil {
			for _, n := range s.exits.List() {
				name := n.DisplayName
				if name == "" {
					name = n.City
				}
				if name == "" {
					name = n.Name
				}
				v := node{ID: n.ID, Name: name, Enabled: n.Enabled}
				if s.selector != nil {
					v.Ready = s.selector.HealthSnapshot()[n.ID].InternetOK
				}
				for _, b := range budgets {
					if b.ID == n.ID {
						v.Primary = b.Fallback
					}
				}
				nodes = append(nodes, v)
			}
		}
		memberJSON(w, struct {
			Budgets []db.ExitBudget `json:"budgets"`
			Nodes   []node          `json:"nodes"`
		}{budgets, nodes}, nil)
	})
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
	started := time.Now()
	regions, plans, e := s.Cloud.Catalog(r.Context())
	s.logCloudRequest("catalog", started, e)
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
	started := time.Now()
	offer, e := s.Cloud.Quote(r.Context(), body.Actor, body.Region, body.Plan, body.ReplaceID)
	s.logCloudRequest("quote", started, e)
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
	started := time.Now()
	op, e := s.Cloud.Confirm(r.Context(), body.Actor, r.PathValue("id"))
	s.logCloudRequest("confirm", started, e)
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

// Pre-purchase failures happen before an operation exists, so retain safe diagnostics in journald.
func (s *Server) logCloudRequest(phase string, started time.Time, err error) {
	fields := []any{"phase", phase, "duration_ms", time.Since(started).Milliseconds()}
	if err == nil {
		s.log.Info("cloud request completed", fields...)
		return
	}
	fields = append(fields, "error_code", cloud.ErrorCode(err))
	var failure cloud.APIError
	if errors.As(err, &failure) {
		fields = append(fields, "http_status", failure.Status)
	}
	s.log.Warn("cloud request failed", fields...)
}
