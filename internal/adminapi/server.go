package adminapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/config"
)

// maxAdminJSONBody caps JSON bodies on mutating Admin API routes (DoS on loopback via SSH tunnel).
const maxAdminJSONBody = 16384

// Server serves provisioning HTTP on loopback only (caller should bind 127.0.0.1).
type Server struct {
	log    *slog.Logger
	users  *auth.Manager
	spec   *config.Spec
	mux    *http.ServeMux
	srv    *http.Server
	lim    *visitorLimiter
	tokenH [32]byte
}

// NewServer validates listen address is loopback.
func NewServer(listen, token string, users *auth.Manager, spec *config.Spec, log *slog.Logger) (*Server, error) {
	if token == "" {
		return nil, errors.New("adminapi: empty admin token")
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, err
	}
	if host != "127.0.0.1" && host != "localhost" {
		return nil, errors.New("adminapi: listen must be 127.0.0.1 or localhost")
	}
	if log == nil {
		log = slog.Default()
	}
	s := &Server{
		log:    log,
		users:  users,
		spec:   spec,
		mux:    http.NewServeMux(),
		lim:    newVisitorLimiter(30, 60, 256),
		tokenH: sha256.Sum256([]byte(token)),
	}
	if err := s.routes(); err != nil {
		return nil, err
	}
	s.srv = &http.Server{
		Addr:              listen,
		Handler:           s.authMiddleware(s.mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	return s, nil
}

func (s *Server) decodeAdminJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminJSONBody)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return false
		}
		http.Error(w, "bad json", http.StatusBadRequest)
		return false
	}
	return true
}

func (s *Server) routes() error {
	adminHandler, err := newAdminStaticHandler()
	if err != nil {
		return err
	}
	s.mux.Handle("GET /admin/", adminHandler)
	s.mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusFound)
	})
	s.mux.HandleFunc("GET /v1/users", s.handleListUsers)
	s.mux.HandleFunc("PATCH /v1/users/{uuid}", s.handlePatchUser)
	s.mux.HandleFunc("DELETE /v1/users/{uuid}", s.handleDeleteUser)
	s.mux.HandleFunc("POST /v1/users", s.handlePostUser)
	s.mux.HandleFunc("GET /v1/users/{uuid}/client", s.handleGetClient)
	return nil
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin") {
			next.ServeHTTP(w, r)
			return
		}
		if !s.lim.allow(clientIP(r)) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		gh := sha256.Sum256([]byte(got))
		if subtle.ConstantTimeCompare(gh[:], s.tokenH[:]) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type postUserReq struct {
	Name string `json:"name"`
}

type postUserResp struct {
	User auth.User `json:"user"`
}

func (s *Server) handlePostUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var body postUserReq
	if !s.decodeAdminJSON(w, r, &body) {
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		http.Error(w, "bad name", http.StatusBadRequest)
		return
	}
	u, err := s.users.AddUser(name)
	if err != nil {
		s.log.Error("add user", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(postUserResp{User: u})
}

type getClientResp struct {
	XrayClientJSON   map[string]any `json:"xray_client_json"`
	VLESSURI         string         `json:"vless_uri"`
	FullConfigBase64 string         `json:"full_xray_config_base64,omitempty"`
}

func (s *Server) handleGetClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	id := r.PathValue("uuid")
	if id == "" {
		http.Error(w, "uuid", http.StatusBadRequest)
		return
	}
	u, ok := s.users.Lookup(id)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	exp, err := config.BuildClientExport(s.spec, u)
	if err != nil {
		s.log.Error("client export", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	_, fullJSON, err := config.FullClientXRayJSON(s.spec, u)
	if err != nil {
		s.log.Error("full config", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	resp := getClientResp{
		XrayClientJSON:   exp.XRayOutboundJSON,
		VLESSURI:         exp.VLESSURI,
		FullConfigBase64: base64.StdEncoding.EncodeToString(fullJSON),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	users := s.users.List()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(users)
}

type patchUserReq struct {
	Name string `json:"name"`
}

func (s *Server) handlePatchUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	id := r.PathValue("uuid")
	if id == "" {
		http.Error(w, "uuid", http.StatusBadRequest)
		return
	}
	var body patchUserReq
	if !s.decodeAdminJSON(w, r, &body) {
		return
	}
	u, err := s.users.RenameUser(id, body.Name)
	if errors.Is(err, auth.ErrUserNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if errors.Is(err, auth.ErrEmptyUserName) {
		http.Error(w, "bad name", http.StatusBadRequest)
		return
	}
	if err != nil {
		s.log.Error("rename user", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		User auth.User `json:"user"`
	}{User: u})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	id := r.PathValue("uuid")
	if id == "" {
		http.Error(w, "uuid", http.StatusBadRequest)
		return
	}
	if err := s.users.RemoveUser(id); err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.log.Error("remove user", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Start runs the HTTP server (non-TLS).
func (s *Server) Start() error {
	s.log.Info("admin API listening", "addr", s.srv.Addr)
	return s.srv.ListenAndServe()
}

// Shutdown stops the server.
func (s *Server) Shutdown() error {
	return s.srv.Close()
}
