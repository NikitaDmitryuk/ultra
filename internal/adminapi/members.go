package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/jackc/pgx/v5"
)

type MemberService struct {
	Repo          *db.MemberRepo
	Subscriptions *db.SubscriptionRepo
	Apply         func(context.Context) error
	mu            sync.Mutex
}

func (m *MemberService) reconcile(ctx context.Context) error {
	snapshot, e := m.Repo.Snapshot(ctx)
	if e != nil || len(snapshot) == 0 {
		return e
	}
	if m.Apply == nil {
		return errors.New("configuration application unavailable")
	}
	if e = m.Apply(ctx); e != nil {
		return e
	}
	return m.Repo.Acknowledge(ctx, snapshot)
}
func (m *MemberService) Run(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			c, cancel := context.WithTimeout(ctx, 20*time.Second)
			_ = m.reconcile(c)
			cancel()
			m.mu.Unlock()
		}
	}
}
func (s *Server) memberRoutes() {
	s.mux.HandleFunc("GET /v1/enrollment/group", s.memberGroup)
	s.mux.HandleFunc("PUT /v1/enrollment/group", s.memberGroup)
	s.mux.HandleFunc("GET /v1/enrollment/invites", s.memberInvites)
	s.mux.HandleFunc("POST /v1/enrollment/invites", s.memberInvites)
	s.mux.HandleFunc("POST /v1/enrollment/invites/{id}/cancel", s.memberInvites)
	s.mux.HandleFunc("POST /v1/members/enroll", s.memberEnroll)
	s.mux.HandleFunc("GET /v1/members", s.memberRead)
	s.mux.HandleFunc("GET /v1/members/traffic", s.memberTraffic)
	s.mux.HandleFunc("GET /v1/members/{id}/traffic", s.memberTraffic)
	s.mux.HandleFunc("GET /v1/members/{id}", s.memberRead)
	s.mux.HandleFunc("POST /v1/members/{id}/action", s.memberAction)
	s.mux.HandleFunc("POST /v1/members/{id}/subscription", s.memberSubscription)
}
func (s *Server) requireMembers(w http.ResponseWriter) bool {
	w.Header().Set("Cache-Control", "no-store")
	if s.Members == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return false
	}
	return true
}
func memberJSON(w http.ResponseWriter, v any, e error) {
	if e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			http.Error(w, "not found", http.StatusNotFound)
		} else if errors.Is(e, db.ErrEnrollmentDenied) {
			http.Error(w, "enrollment denied", http.StatusForbidden)
		} else {
			http.Error(w, "operation unavailable; retry", http.StatusServiceUnavailable)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func (s *Server) memberGroup(w http.ResponseWriter, r *http.Request) {
	if !s.requireMembers(w) {
		return
	}
	if r.Method == "GET" {
		v, e := s.Members.Repo.Group(r.Context())
		memberJSON(w, v, e)
		return
	}
	var body struct {
		db.VPNGroup
		Actor int64 `json:"actor"`
	}
	if !s.decodeAdminJSON(w, r, &body) {
		return
	}
	v, e := s.Members.Repo.PutGroup(r.Context(), body.VPNGroup, body.Actor)
	memberJSON(w, v, e)
}
func (s *Server) memberInvites(w http.ResponseWriter, r *http.Request) {
	if !s.requireMembers(w) {
		return
	}
	if r.Method == "GET" {
		v, e := s.Members.Repo.Invites(r.Context())
		memberJSON(w, v, e)
		return
	}
	var body struct {
		RecipientName string `json:"recipient_name"`
		Recipient     int64  `json:"recipient"`
		Actor         int64  `json:"actor"`
	}
	if !s.decodeAdminJSON(w, r, &body) {
		return
	}
	if r.PathValue("id") != "" {
		id, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if e != nil {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}
		e = s.Members.Repo.CancelInvite(r.Context(), id, body.Actor)
		memberJSON(w, map[string]bool{"cancelled": e == nil}, e)
		return
	}
	token, e := s.Members.Repo.Invite(r.Context(), body.Recipient, body.Actor, body.RecipientName)
	memberJSON(w, map[string]string{"token": token}, e)
}
func (s *Server) memberEnroll(w http.ResponseWriter, r *http.Request) {
	if !s.requireMembers(w) {
		return
	}
	var b struct {
		ID     int64  `json:"telegram_id"`
		Name   string `json:"name"`
		Source string `json:"source"`
		Token  string `json:"token"`
		ChatID int64  `json:"chat_id"`
	}
	if !s.decodeAdminJSON(w, r, &b) {
		return
	}
	m := s.Members
	m.mu.Lock()
	defer m.mu.Unlock()
	v, e := m.Repo.Enroll(r.Context(), b.ID, b.Name, b.Source, b.Token, b.ChatID)
	if e != nil {
		memberJSON(w, nil, e)
		return
	}
	// Persisted enrollment remains retryable when the core is unavailable.
	if e = m.reconcile(r.Context()); e == nil {
		v, e = m.Repo.Get(r.Context(), b.ID)
	} else {
		e = nil
	}
	memberJSON(w, v, e)
}
func (s *Server) memberRead(w http.ResponseWriter, r *http.Request) {
	if !s.requireMembers(w) {
		return
	}
	if r.PathValue("id") == "" {
		v, e := s.Members.Repo.List(r.Context())
		memberJSON(w, v, e)
		return
	}
	id, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if e != nil || id <= 0 {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	v, e := s.Members.Repo.Get(r.Context(), id)
	memberJSON(w, v, e)
}
func (s *Server) memberAction(w http.ResponseWriter, r *http.Request) {
	if !s.requireMembers(w) {
		return
	}
	id, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if e != nil || id <= 0 {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	var b struct {
		Action       string `json:"action"`
		Actor        int64  `json:"actor"`
		ExpectedUUID string `json:"expected_uuid"`
	}
	if !s.decodeAdminJSON(w, r, &b) {
		return
	}
	if b.Actor <= 0 {
		http.Error(w, "bad actor", http.StatusBadRequest)
		return
	}
	m := s.Members
	m.mu.Lock()
	defer m.mu.Unlock()
	switch b.Action {
	case "enable", "disable":
		e = m.Repo.SetActive(r.Context(), id, b.Actor, b.Action == "enable")
	case "reset":
		if m.Subscriptions == nil || !m.Subscriptions.Ready() {
			http.Error(w, "subscription key unavailable", http.StatusServiceUnavailable)
			return
		}
		e = m.Repo.Reset(r.Context(), id, b.Actor, b.ExpectedUUID)
	default:
		http.Error(w, "bad action", http.StatusBadRequest)
		return
	}
	if e != nil {
		memberJSON(w, nil, e)
		return
	}
	_ = m.reconcile(r.Context())
	v, e := m.Repo.Get(r.Context(), id)
	memberJSON(w, v, e)
}
func (s *Server) memberSubscription(w http.ResponseWriter, r *http.Request) {
	if !s.requireMembers(w) {
		return
	}
	id, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if e != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	m, e := s.Members.Repo.Get(r.Context(), id)
	if e != nil {
		memberJSON(w, nil, e)
		return
	}
	if !m.Active || m.Pending {
		http.Error(w, "access unavailable", http.StatusConflict)
		return
	}
	token, e := s.Members.Subscriptions.GetOrCreate(r.Context(), m.UUID)
	memberJSON(w, map[string]string{"token": token}, e)
}

func (s *Server) memberTraffic(w http.ResponseWriter, r *http.Request) {
	if !s.requireMembers(w) {
		return
	}
	var id int64
	if raw := r.PathValue("id"); raw != "" {
		var e error
		id, e = strconv.ParseInt(raw, 10, 64)
		if e != nil || id <= 0 {
			http.Error(w, "invalid member", 400)
			return
		}
		if _, e = s.Members.Repo.Get(r.Context(), id); e != nil {
			memberJSON(w, nil, e)
			return
		}
	}
	result, e := s.Members.Repo.Traffic(r.Context(), id, time.Now())
	memberJSON(w, result, e)
}
