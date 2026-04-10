package adminapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/NikitaDmitryuk/ultra/internal/probe"
	"github.com/NikitaDmitryuk/ultra/internal/trace"
)

// maxAdminJSONBody caps JSON bodies on mutating Admin API routes (DoS on loopback via SSH tunnel).
const maxAdminJSONBody = 16384

// TrafficQuerier is the subset of db.TrafficRepo used by the admin API.
// nil when the DB backend is not configured.
type TrafficQuerier interface {
	GetMonthlyAll(ctx context.Context, year, month int) ([]db.MonthlyTotal, error)
	GetMonthlyUser(ctx context.Context, userUUID string, year, month int) (db.MonthlyTotal, error)
	GetMonthlyHistory(ctx context.Context, months int) ([]db.MonthlyHistoryPoint, error)
	GetLastSeenAll(ctx context.Context) ([]db.UserLastSeen, error)
}

// Server serves provisioning HTTP on loopback only (caller should bind 127.0.0.1).
type Server struct {
	log        *slog.Logger
	users      auth.UserManager
	traffic    TrafficQuerier // nil when DB is not configured
	traceStore *trace.Store   // nil when trace_latency is disabled
	spec       *config.Spec
	mux        *http.ServeMux
	srv        *http.Server
	lim        *visitorLimiter
	tokenH     [32]byte
}

// NewServer validates listen address is loopback.
// traffic and traceStore may be nil when those features are not configured.
func NewServer(listen, token string, users auth.UserManager, traffic TrafficQuerier, traceStore *trace.Store, spec *config.Spec, log *slog.Logger) (*Server, error) {
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
		log:        log,
		users:      users,
		traffic:    traffic,
		traceStore: traceStore,
		spec:       spec,
		mux:        http.NewServeMux(),
		lim:        newVisitorLimiter(30, 60, 256),
		tokenH:     sha256.Sum256([]byte(token)),
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
	s.mux.HandleFunc("GET /v1/users/{uuid}/traffic", s.handleGetUserTraffic)
	s.mux.HandleFunc("GET /v1/traffic/monthly", s.handleGetMonthlyTraffic)
	s.mux.HandleFunc("GET /v1/traffic/history", s.handleGetTrafficHistory)
	s.mux.HandleFunc("GET /v1/traffic/last-seen", s.handleGetLastSeen)
	s.mux.HandleFunc("GET /v1/latency/probe", s.handleLatencyProbe)
	s.mux.HandleFunc("GET /v1/latency/sessions", s.handleLatencySessions)
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

// handleGetUserTraffic returns monthly traffic for a single user.
// Query param: ?month=YYYY-MM (default: current month).
func (s *Server) handleGetUserTraffic(w http.ResponseWriter, r *http.Request) {
	if s.traffic == nil {
		http.Error(w, "traffic stats require database backend", http.StatusNotImplemented)
		return
	}
	id := r.PathValue("uuid")
	if id == "" {
		http.Error(w, "uuid", http.StatusBadRequest)
		return
	}
	if _, ok := s.users.Lookup(id); !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	year, month := parseMonthParam(r)
	total, err := s.traffic.GetMonthlyUser(r.Context(), id, year, month)
	if err != nil {
		s.log.Error("get user traffic", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(total)
}

// handleGetMonthlyTraffic returns monthly traffic for all users.
// Query param: ?month=YYYY-MM (default: current month).
func (s *Server) handleGetMonthlyTraffic(w http.ResponseWriter, r *http.Request) {
	if s.traffic == nil {
		http.Error(w, "traffic stats require database backend", http.StatusNotImplemented)
		return
	}
	year, month := parseMonthParam(r)
	totals, err := s.traffic.GetMonthlyAll(r.Context(), year, month)
	if err != nil {
		s.log.Error("get monthly traffic", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	if totals == nil {
		totals = []db.MonthlyTotal{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(totals)
}

// parseMonthParam parses ?month=YYYY-MM from the request, defaulting to the current month.
func parseMonthParam(r *http.Request) (year, month int) {
	now := time.Now()
	y, m, _ := now.Date()
	year, month = y, int(m)
	if s := r.URL.Query().Get("month"); s != "" {
		var yy, mm int
		if _, err := fmt.Sscanf(s, "%d-%02d", &yy, &mm); err == nil && yy > 0 && mm >= 1 && mm <= 12 {
			year, month = yy, mm
		}
	}
	return year, month
}

// handleGetTrafficHistory returns aggregated monthly traffic totals across all users
// for the last N calendar months (oldest→newest).
// Query param: ?months=N (default 6, max 24).
func (s *Server) handleGetTrafficHistory(w http.ResponseWriter, r *http.Request) {
	if s.traffic == nil {
		http.Error(w, "traffic stats require database backend", http.StatusNotImplemented)
		return
	}
	months := 6
	if v := r.URL.Query().Get("months"); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			if n > 24 {
				n = 24
			}
			months = n
		}
	}
	history, err := s.traffic.GetMonthlyHistory(r.Context(), months)
	if err != nil {
		s.log.Error("get traffic history", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	if history == nil {
		history = []db.MonthlyHistoryPoint{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(history)
}

// handleGetLastSeen returns the most recent activity timestamp for each user.
func (s *Server) handleGetLastSeen(w http.ResponseWriter, r *http.Request) {
	if s.traffic == nil {
		http.Error(w, "traffic stats require database backend", http.StatusNotImplemented)
		return
	}
	seen, err := s.traffic.GetLastSeenAll(r.Context())
	if err != nil {
		s.log.Error("get last seen", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	if seen == nil {
		seen = []db.UserLastSeen{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(seen)
}

// handleLatencyProbe measures bridge→exit TCP round-trip and returns the result as JSON.
// It is available on bridge role only (exit spec has no Exit.Address/Port set in that direction).
func (s *Server) handleLatencyProbe(w http.ResponseWriter, r *http.Request) {
	exitAddr := fmt.Sprintf("%s:%d", s.spec.Exit.Address, s.spec.Exit.Port)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rtt, err := probe.DialTCP(ctx, exitAddr)

	type probeResult struct {
		BridgeToExitTCPMs int64  `json:"bridge_to_exit_tcp_ms"`
		ExitAddr          string `json:"exit_addr"`
		Error             string `json:"error,omitempty"`
		MeasuredAt        string `json:"measured_at"`
	}
	res := probeResult{
		ExitAddr:   exitAddr,
		MeasuredAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err != nil {
		res.Error = err.Error()
	} else {
		res.BridgeToExitTCPMs = rtt.Milliseconds()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// handleLatencySessions returns recent per-connection timing traces.
// Returns 501 when trace_latency is not enabled in spec.
func (s *Server) handleLatencySessions(w http.ResponseWriter, r *http.Request) {
	if s.traceStore == nil {
		http.Error(w, `trace_latency not enabled — set "trace_latency": true in spec.json`, http.StatusNotImplemented)
		return
	}
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}

	sessions := s.traceStore.Recent(limit)

	type sessionJSON struct {
		SessionID   uint32            `json:"session_id"`
		StartedAt   string            `json:"started_at"`
		Destination string            `json:"destination"`
		OutboundTag string            `json:"outbound_tag,omitempty"`
		StagesMS    map[string]int64  `json:"stages_ms"`
	}
	out := make([]sessionJSON, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, sessionJSON{
			SessionID:   s.ID,
			StartedAt:   s.StartedAt.UTC().Format(time.RFC3339Nano),
			Destination: s.Destination,
			OutboundTag: s.OutboundTag,
			StagesMS:    s.StageDeltasMS(),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
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
