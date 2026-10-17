package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/jackc/pgx/v5"
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
func (s *Server) resolveSubscriptionUser(w http.ResponseWriter, r *http.Request) (string, auth.User, bool) {
	w.Header().Set("Cache-Control", "no-store")
	if s.Subscriptions == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return "", auth.User{}, false
	}
	id, err := s.Subscriptions.Resolve(r.Context(), r.PathValue("token"))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.NotFound(w, r)
		} else {
			http.Error(w, "subscription unavailable", http.StatusServiceUnavailable)
		}
		return "", auth.User{}, false
	}
	u, ok := s.users.Lookup(id)
	if !ok || !u.IsActive || u.Kind == "socks5" {
		http.NotFound(w, r)
		return "", auth.User{}, false
	}
	return id, u, true
}

func (s *Server) handleSubscription(w http.ResponseWriter, r *http.Request) {
	id, u, ok := s.resolveSubscriptionUser(w, r)
	if !ok {
		return
	}
	s.renderSubscription(w, r, id, u, nil)
}

// quotaHeaders is supplied only by the cache export, scoped to one confirmed token.
func (s *Server) renderSubscription(w http.ResponseWriter, r *http.Request, id string, u auth.User, quotaHeaders http.Header) {
	w.Header().Set("Cache-Control", "no-store")
	transport := r.URL.Query().Get("transport")
	format, err := config.ResolveSubscriptionFormat(r.URL.Query().Get("format"), transport, r.UserAgent(), s.spec.HappDefaultJSON)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	exportSpec := s.spec
	preview := r.URL.Query().Get("preview")
	if preview != "" {
		if (preview != "reserve" && preview != "reserve-test") || format != "happ" || transport != "" {
			http.Error(w, "unsupported subscription preview", http.StatusBadRequest)
			return
		}
		permissions, ok := s.Subscriptions.(interface {
			IsAdminOwner(context.Context, string) (bool, error)
		})
		if !ok {
			http.NotFound(w, r)
			return
		}
		allowed, permissionErr := permissions.IsAdminOwner(r.Context(), id)
		if permissionErr != nil {
			http.Error(w, "subscription unavailable", http.StatusServiceUnavailable)
			return
		}
		if !allowed {
			http.NotFound(w, r)
			return
		}
		if len(s.spec.SubscriptionPreviewBridges) == 0 {
			http.Error(w, "preview unavailable", http.StatusServiceUnavailable)
			return
		}
		s.capturePreviewUserAgent(r.UserAgent())
		copySpec := *s.spec
		copySpec.SubscriptionBridges = s.spec.SubscriptionPreviewBridges
		exportSpec = &copySpec
	}
	w.Header().Set("Vary", "User-Agent")
	w.Header().Set("profile-title", "ultra")
	w.Header().Set("profile-update-interval", "1")
	_, _, health, nodes := s.clientExitSelection(u)
	if quotaHeaders == nil {
		s.setSubscriptionQuota(r.Context(), w.Header(), u.AccountID, nodes)
	} else {
		for key, values := range quotaHeaders {
			w.Header()[key] = append([]string(nil), values...)
		}
	}
	var experiment *config.ExperimentalProfile
	if specFile := s.spec.ExperimentalProfileFile; specFile != "" && transport == "" && preview == "" {
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
		profiles, err := subscriptionHapp(exportSpec, u, nodes, health)
		if preview == "reserve-test" {
			profiles, err = config.BuildHappFaultProfiles(exportSpec, u)
		}
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
		"inbounds": []any{
			map[string]any{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": map[string]any{"udp": true}},
		},
		"outbounds": []any{
			exp.XRayOutboundJSON,
		}, "routing": map[string]any{"rules": []any{map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "proxy"}}}}
}

// Only authorised acceptance requests enter this bounded diagnostic. No request
// path, token, remote address, owner identifier or query is logged.
func (s *Server) capturePreviewUserAgent(ua string) {
	for {
		n := s.previewUACount.Load()
		if n >= 8 {
			return
		}
		if s.previewUACount.CompareAndSwap(n, n+1) {
			break
		}
	}
	if len(ua) > 256 {
		ua = ua[:256]
	}
	s.log.Info("subscription preview client", "user_agent", ua)
}
