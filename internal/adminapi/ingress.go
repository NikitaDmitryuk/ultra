package adminapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

type ingressStatus struct {
	ID                  string    `json:"id"`
	Published           bool      `json:"published"`
	Ready               bool      `json:"ready"`
	Phase               string    `json:"phase"`
	CheckedAt           time.Time `json:"checked_at"`
	CertificateNotAfter time.Time `json:"certificate_not_after,omitempty"`
	Reload              any       `json:"reload,omitempty"`
}

func (s *Server) publicIngressStatus(ctx context.Context) []ingressStatus {
	result := []ingressStatus{}
	if p := s.spec.PrimaryXHTTP; p != nil {
		state := ingressStatus{ID: "primary", Published: s.spec.PrimaryXHTTPIsPublished(), Phase: "public_tls", CheckedAt: time.Now().UTC()}
		c, err := (&tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Second}, Config: &tls.Config{ServerName: p.ServerName, MinVersion: tls.VersionTLS12}}).DialContext(
			ctx,
			"tcp",
			net.JoinHostPort(p.Host, strconv.Itoa(p.Port)),
		)
		if err == nil {
			if certs := c.(*tls.Conn).ConnectionState().PeerCertificates; len(certs) > 0 {
				state.CertificateNotAfter = certs[0].NotAfter
			}
			_ = c.Close()
			state.Phase = "local_backend"
			backend, err := (&net.Dialer{Timeout: time.Second}).DialContext(
				ctx,
				"tcp",
				net.JoinHostPort("127.0.0.1", strconv.Itoa(p.BackendPort)),
			)
			if err == nil {
				_ = backend.Close()
				state.Ready = true
				state.Phase = "server_path_ready"
			}
		}
		if s.ReloadStatus != nil {
			state.Reload = s.ReloadStatus()
		}
		result = append(result, state)
	}

	return result
}

func (s *Server) handleIngressNotice(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Key  string `json:"key"`
		Text string `json:"text"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || payload.Key == "" || len(payload.Key) > 100 || len(payload.Text) == 0 ||
		len(payload.Text) > 3000 {
		http.Error(w, "invalid notice", 400)
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		http.Error(w, "invalid notice", 400)
		return
	}
	repo, ok := s.Subscriptions.(interface {
		EnqueueIngressNotice(context.Context, string, string) (int64, error)
	})
	if !ok {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	count, err := repo.EnqueueIngressNotice(r.Context(), payload.Key, payload.Text)
	if err != nil {
		http.Error(w, "cannot enqueue notice", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"queued": count})
}
