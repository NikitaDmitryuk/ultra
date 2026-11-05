package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/db"
)

// DecodePersonalPreferences accepts exactly four boolean fields, including false.
func DecodePersonalPreferences(r io.Reader) (db.PersonalNotificationPreferences, error) {
	var body struct {
		Credentials  *bool `json:"credentials"`
		Access       *bool `json:"access"`
		Quota        *bool `json:"quota"`
		Availability *bool `json:"availability"`
	}
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if e := d.Decode(&body); e != nil {
		return db.PersonalNotificationPreferences{}, e
	}
	if body.Credentials == nil || body.Access == nil || body.Quota == nil || body.Availability == nil {
		return db.PersonalNotificationPreferences{}, errors.New("four boolean preferences required")
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return db.PersonalNotificationPreferences{}, errors.New("trailing JSON")
	}
	return db.PersonalNotificationPreferences{
		Credentials:  *body.Credentials,
		Access:       *body.Access,
		Quota:        *body.Quota,
		Availability: *body.Availability,
	}, nil
}
func (s *Server) personalNotificationRoutes() {
	s.mux.HandleFunc("GET /v1/members/{id}/notifications", s.personalPreferences)
	s.mux.HandleFunc("PUT /v1/members/{id}/notifications", s.personalPreferences)
	s.mux.HandleFunc("POST /v1/personal-notifications/observe", s.personalObserve)
	s.mux.HandleFunc("POST /v1/personal-notifications/claim", s.personalClaim)
	s.mux.HandleFunc("POST /v1/personal-notifications/{id}/prepare", s.personalPrepare)
	s.mux.HandleFunc("POST /v1/personal-notifications/{id}/complete", s.personalComplete)
}
func (s *Server) personalReady(w http.ResponseWriter) bool {
	w.Header().Set("Cache-Control", "no-store")
	if s.PersonalNotifications == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return false
	}
	return true
}
func (s *Server) personalPreferences(w http.ResponseWriter, r *http.Request) {
	if !s.personalReady(w) {
		return
	}
	id, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if e != nil || id <= 0 {
		http.Error(w, "bad id", 400)
		return
	}
	if r.Method == "PUT" {
		p, e := DecodePersonalPreferences(http.MaxBytesReader(w, r.Body, 1024))
		if e != nil {
			http.Error(w, "four boolean preferences required", 400)
			return
		}
		if e = s.PersonalNotifications.PutPreferences(r.Context(), id, p); e != nil {
			memberJSON(w, nil, e)
			return
		}
	}
	p, e := s.PersonalNotifications.Preferences(r.Context(), id)
	memberJSON(w, p, e)
}
func (s *Server) personalObserve(w http.ResponseWriter, r *http.Request) {
	if !s.personalReady(w) {
		return
	}
	if s.PersonalRouteSnapshot == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	e := s.PersonalNotifications.Observe(r.Context(), s.PersonalRouteSnapshot(), time.Now().UTC())
	memberJSON(w, map[string]bool{"ok": e == nil}, e)
}
func (s *Server) personalClaim(w http.ResponseWriter, r *http.Request) {
	if !s.personalReady(w) {
		return
	}
	n, e := s.PersonalNotifications.Claim(r.Context())
	memberJSON(w, n, e)
}
func (s *Server) personalRequest(w http.ResponseWriter, r *http.Request) (db.PersonalNotification, bool) {
	var n db.PersonalNotification
	if !s.personalReady(w) {
		return n, false
	}
	if !s.decodeAdminJSON(w, r, &n) {
		return n, false
	}
	id, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if e != nil || id != n.ID || n.Attempts <= 0 {
		http.Error(w, "invalid claim", 400)
		return n, false
	}
	return n, true
}
func (s *Server) personalPrepare(w http.ResponseWriter, r *http.Request) {
	n, ok := s.personalRequest(w, r)
	if !ok {
		return
	}
	eligible, e := s.PersonalNotifications.Eligible(r.Context(), &n)
	if e != nil {
		personalPreparationJSON(w, n, false, "", e)
		return
	}

	token := ""
	if eligible && n.Category == "credentials" {
		store, ok := s.Subscriptions.(interface {
			Existing(context.Context, string) (string, error)
		})
		if !ok {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		token, e = store.Existing(r.Context(), n.UUID)
		if e != nil {
			http.Error(w, "current subscription unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	personalPreparationJSON(w, n, eligible, token, nil)
}
func (s *Server) personalComplete(w http.ResponseWriter, r *http.Request) {
	if !s.personalReady(w) {
		return
	}
	var body struct {
		Notification db.PersonalNotification `json:"notification"`
		Sent         bool                    `json:"sent"`
		Terminal     bool                    `json:"terminal"`
		Deferred     bool                    `json:"deferred"`
		DelaySeconds int                     `json:"delay_seconds"`
	}
	if !s.decodeAdminJSON(w, r, &body) {
		return
	}
	id, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if e != nil || id != body.Notification.ID || body.Notification.Attempts <= 0 || body.DelaySeconds < 0 || body.DelaySeconds > 86400 ||
		(body.Deferred && (body.Sent || body.Terminal)) ||
		(body.Sent && body.Terminal) {
		http.Error(w, "invalid claim", 400)
		return
	}
	if body.Deferred {
		e = s.PersonalNotifications.Defer(r.Context(), body.Notification, time.Duration(body.DelaySeconds)*time.Second)
	} else {
		e = s.PersonalNotifications.Complete(r.Context(), body.Notification, body.Sent, body.Terminal, time.Duration(body.DelaySeconds)*time.Second)
	}

	memberJSON(w, map[string]bool{"ok": e == nil}, e)
}

// Pending confirmation is a normal wait, distinct from unexpected API failures.
func personalPreparationJSON(w http.ResponseWriter, n db.PersonalNotification, eligible bool, token string, err error) {
	pending := errors.Is(err, db.ErrPersonalNotificationPending)
	if pending {
		err = nil
		eligible = false
		token = ""
	}
	memberJSON(w, map[string]any{"eligible": eligible, "pending": pending, "notification": n, "token": token}, err)
}
