package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type SubscriptionStore interface {
	Rotate(context.Context, string) (string, error)
	Revoke(context.Context, string) error
	Resolve(context.Context, string) (string, error)
}

func (s *Server) handleRotateSubscription(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.Subscriptions == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if u, ok := s.users.Lookup(r.PathValue("uuid")); !ok || !u.IsActive || u.Kind == "socks5" {
		http.NotFound(w, r)
		return
	}
	token, err := s.Subscriptions.Rotate(r.Context(), r.PathValue("uuid"))
	if err != nil {
		http.Error(w, "cannot issue subscription", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
}
func (s *Server) handleRevokeSubscription(w http.ResponseWriter, r *http.Request) {
	if s.Subscriptions == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := s.Subscriptions.Revoke(r.Context(), r.PathValue("uuid")); err != nil {
		http.Error(w, "cannot revoke subscription", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) handleSubscription(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.Subscriptions == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	id, err := s.Subscriptions.Resolve(r.Context(), r.PathValue("token"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	u, ok := s.users.Lookup(id)
	if !ok || !u.IsActive || u.Kind == "socks5" {
		http.NotFound(w, r)
		return
	}
	_, _, health, nodes := s.clientExitSelection(u)
	uris, err := subscriptionURIs(s.spec, u, nodes, health)
	if err != nil {
		http.Error(w, "configuration unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("profile-title", "ultra")
	w.Header().Set("profile-update-interval", "1")
	_, _ = w.Write([]byte(strings.Join(uris, "\n") + "\n"))
}
