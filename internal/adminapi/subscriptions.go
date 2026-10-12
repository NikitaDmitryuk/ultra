package adminapi

import (
	"context"
	"encoding/json"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"net/http"
	"net/url"
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
	format := r.URL.Query().Get("format")
	if format != "" && format != "happ" && format != "uri" {
		http.Error(w, "unknown subscription format", http.StatusBadRequest)
		return
	}
	transport := r.URL.Query().Get("transport")
	if (transport != "" && transport != "xhttp-tls") || (transport != "" && format == "happ") {
		http.Error(w, "unsupported subscription transport or format", http.StatusBadRequest)
		return
	}
	w.Header().Set("Vary", "User-Agent")
	w.Header().Set("profile-title", "ultra")
	w.Header().Set("profile-update-interval", "1")
	_, _, health, nodes := s.clientExitSelection(u)
	var experiment *config.ExperimentalProfile
	if specFile := s.spec.ExperimentalProfileFile; specFile != "" && transport == "" {
		if permissions, ok := s.Subscriptions.(interface {
			IsAdminOwner(context.Context, string) (bool, error)
		}); ok {
			allowed, err := permissions.IsAdminOwner(r.Context(), id)
			if err == nil && allowed {
				experiment, _ = config.LoadExperimentalProfile(specFile)
			}
		}
	}
	if format == "happ" {
		profiles, err := subscriptionHapp(s.spec, u, nodes, health)
		if err != nil {
			http.Error(w, "configuration unavailable", http.StatusServiceUnavailable)
			return
		}
		if experiment != nil {
			exp := config.BuildExperimentalExport(s.spec, u, experiment)
			profile := experimentalHapp(exp, "Эксперимент · XHTTP TLS")
			profiles = append(profiles, profile)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(profiles)
		return
	}
	uris, err := subscriptionURIs(s.spec, u, nodes, health, transport)
	if err != nil {
		http.Error(w, "configuration unavailable", http.StatusServiceUnavailable)
		return
	}
	if experiment != nil {
		exp := config.BuildExperimentalExport(s.spec, u, experiment)
		uris = append(uris, labelSubscriptionURI(exp.VLESSURI, "Эксперимент · XHTTP TLS"))
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(strings.Join(uris, "\n") + "\n"))
}

func labelSubscriptionURI(raw, name string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Fragment = name
	return u.String()
}
func experimentalHapp(exp *config.ClientExport, name string) map[string]any {
	exp.XRayOutboundJSON["tag"] = "proxy"
	return map[string]any{"remarks": name, "log": map[string]any{"loglevel": "warning"},
		"inbounds":  []any{map[string]any{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": map[string]any{"udp": true}}},
		"outbounds": []any{exp.XRayOutboundJSON}, "routing": map[string]any{"rules": []any{map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "proxy"}}}}
}
