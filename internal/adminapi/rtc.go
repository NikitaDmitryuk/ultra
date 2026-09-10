package adminapi

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/NikitaDmitryuk/ultra/internal/rtcingress"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func (s *Server) rtcRoutes() {
	s.mux.HandleFunc("GET /v1/features", func(w http.ResponseWriter, r *http.Request) {
		memberJSON(w, map[string]bool{"rtc": s.RTC != nil && s.spec.RTCService.Enabled}, nil)
	})
	s.mux.HandleFunc("GET /v1/rtc/traffic", s.rtcTraffic)
	s.mux.HandleFunc("/v1/members/{id}/rtc", s.memberRTC)
	s.mux.HandleFunc("GET /v1/members/{id}/rtc/guide", s.memberRTC)
	s.mux.HandleFunc("GET /v1/members/{id}/rtc/profile", s.memberRTC)
	s.mux.HandleFunc("GET /v1/members/{id}/rtc/traffic", s.memberRTC)
	s.mux.HandleFunc("POST /v1/members/{id}/rtc/retry", s.memberRTC)
}
func (s *Server) rtcAvailable(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	if s.RTC == nil || !s.spec.RTCService.Enabled {
		http.NotFound(w, r)
		return false
	}
	return true
}
func rtcError(w http.ResponseWriter, e error) {
	code := 503
	msg := "unavailable"
	var pe *pgconn.PgError
	switch {
	case errors.Is(e, rtcingress.ErrInvalidRoom):
		code = 400
		msg = "invalid_room"
	case errors.Is(e, db.ErrRTCCapacity):
		code = 409
		msg = "capacity"
	case errors.Is(e, db.ErrRTCRate):
		code = 429
		msg = "rate_limited"
	case errors.Is(e, db.ErrEnrollmentDenied):
		code = 403
	case errors.As(e, &pe) && pe.Code == "23505":
		code = 409
		msg = "room_in_use"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	memberJSON(w, map[string]string{"code": msg}, nil)
}
func (s *Server) rtcTraffic(w http.ResponseWriter, r *http.Request) {
	if !s.rtcAvailable(w, r) {
		return
	}
	v, e := s.RTC.Repo.Usage(r.Context(), "")
	memberJSON(w, v, e)
}
func (s *Server) memberRTC(w http.ResponseWriter, r *http.Request) {
	if !s.rtcAvailable(w, r) || !s.requireMembers(w) {
		return
	}
	id, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if e != nil || id <= 0 {
		http.NotFound(w, r)
		return
	}
	m, e := s.Members.Repo.Get(r.Context(), id)
	if e != nil {
		memberJSON(w, nil, e)
		return
	}
	if !m.Active || m.Pending {
		http.Error(w, "unavailable", http.StatusForbidden)
		return
	}
	switch r.URL.Path {
	case "/v1/members/" + r.PathValue("id") + "/rtc/guide":
		memberJSON(w, s.RTC.Content.Guide, nil)
		return
	case "/v1/members/" + r.PathValue("id") + "/rtc/traffic":
		v, e := s.RTC.Repo.Usage(r.Context(), m.UUID)
		memberJSON(w, v, e)
		return
	case "/v1/members/" + r.PathValue("id") + "/rtc/profile":
		v, e := s.RTC.Profile(r.Context(), m.UUID)
		if e != nil {
			rtcError(w, e)
			return
		}
		memberJSON(w, map[string]string{"profile": v}, nil)
		return
	case "/v1/members/" + r.PathValue("id") + "/rtc/retry":
		v, e := s.RTC.Put(r.Context(), m.UUID, "", true)
		if e != nil {
			rtcError(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(202)
		memberJSON(w, v, nil)
		return
	}
	switch r.Method {
	case "GET":
		v, e := s.RTC.Repo.Get(r.Context(), m.UUID)
		if errors.Is(e, pgx.ErrNoRows) {
			memberJSON(w, map[string]any{"enabled": false, "state": "absent"}, nil)
			return
		}
		memberJSON(w, v, e)
	case "PUT":
		var body struct {
			URL string `json:"url"`
		}
		if !s.decodeAdminJSON(w, r, &body) {
			return
		}
		v, e := s.RTC.Put(r.Context(), m.UUID, body.URL, false)
		if e != nil {
			rtcError(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(202)
		memberJSON(w, v, nil)
	case "DELETE":
		if e := s.RTC.Delete(r.Context(), m.UUID); e != nil {
			rtcError(w, e)
			return
		}
		memberJSON(w, map[string]bool{"enabled": false}, nil)
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
