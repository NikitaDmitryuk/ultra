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

	"golang.org/x/sync/errgroup"
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
	log     *slog.Logger
	users   auth.UserManager
	traffic TrafficQuerier // nil when DB is not configured
	spec    *config.Spec
	// statPeek reads a cumulative Xray stats counter by name (optional; used for legacy SOCKS5 traffic).
	statPeek func(string) int64
	mux      *http.ServeMux
	srv      *http.Server
	lim      *visitorLimiter
	tokenH   [32]byte
}

// NewServer validates listen address is loopback.
// traffic may be nil when the DB backend is not configured.
func NewServer(
	listen, token string,
	users auth.UserManager,
	traffic TrafficQuerier,
	spec *config.Spec,
	log *slog.Logger,
	statPeek func(string) int64,
) (*Server, error) {
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
		log:      log,
		users:    users,
		traffic:  traffic,
		spec:     spec,
		statPeek: statPeek,
		mux:      http.NewServeMux(),
		lim:      newVisitorLimiter(30, 60, 256),
		tokenH:   sha256.Sum256([]byte(token)),
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
	s.mux.HandleFunc("DELETE /v1/users/{uuid}/purge", s.handlePurgeUser)
	s.mux.HandleFunc("POST /v1/users/{uuid}/enable", s.handleEnableUser)
	s.mux.HandleFunc("POST /v1/users/{uuid}/rotate", s.handleRotateUser)
	s.mux.HandleFunc("POST /v1/users", s.handlePostUser)
	s.mux.HandleFunc("GET /v1/users/{uuid}/client", s.handleGetClient)
	s.mux.HandleFunc("GET /v1/users/{uuid}/traffic", s.handleGetUserTraffic)
	s.mux.HandleFunc("GET /v1/traffic/monthly", s.handleGetMonthlyTraffic)
	s.mux.HandleFunc("GET /v1/traffic/history", s.handleGetTrafficHistory)
	s.mux.HandleFunc("GET /v1/traffic/last-seen", s.handleGetLastSeen)
	s.mux.HandleFunc("GET /v1/health", s.handleHealth)
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
	Kind string `json:"kind"` // "vless" (default) or "socks5"
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
	kind := strings.TrimSpace(strings.ToLower(body.Kind))
	if kind == "" {
		kind = "vless"
	}
	u, err := s.users.AddUser(kind, name)
	if errors.Is(err, auth.ErrInvalidUserKind) {
		http.Error(w, "invalid kind", http.StatusBadRequest)
		return
	}
	if errors.Is(err, auth.ErrSocksPortsExhausted) {
		http.Error(w, "no free socks5 port", http.StatusServiceUnavailable)
		return
	}
	if err != nil {
		s.log.Error("add user", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(postUserResp{User: u})
}

type getClientResp struct {
	XrayClientJSON   map[string]any `json:"xray_client_json,omitempty"`
	VLESSURI         string         `json:"vless_uri,omitempty"`
	FullConfigBase64 string         `json:"full_xray_config_base64,omitempty"`
	Socks5URI        string         `json:"socks5_uri,omitempty"`
	Host             string         `json:"host,omitempty"`
	Port             int            `json:"port,omitempty"`
	Username         string         `json:"username,omitempty"`
	Password         string         `json:"password,omitempty"`
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
	if id == auth.LegacySocksUserUUID {
		s5 := s.spec.SOCKS5
		if s5 == nil || !s5.Enabled {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		host := strings.TrimSpace(s.spec.PublicHost)
		uri := config.Socks5ClientURI(host, s5.Port, s5.Username, s5.Password)
		resp := getClientResp{
			Socks5URI: uri, Host: host, Port: s5.Port,
			Username: s5.Username, Password: s5.Password,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	u, ok := s.users.Lookup(id)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if u.Kind == "socks5" {
		if u.SocksPort == nil || *u.SocksPort <= 0 || u.SocksUsername == "" || u.SocksPassword == "" {
			http.Error(w, "incomplete socks5 user", http.StatusInternalServerError)
			return
		}
		host := strings.TrimSpace(s.spec.PublicHost)
		uri := config.Socks5ClientURI(host, *u.SocksPort, u.SocksUsername, u.SocksPassword)
		resp := getClientResp{
			Socks5URI: uri, Host: host, Port: *u.SocksPort,
			Username: u.SocksUsername, Password: u.SocksPassword,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
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
	includeDisabled := false
	switch strings.TrimSpace(strings.ToLower(r.URL.Query().Get("include_disabled"))) {
	case "1", "true", "yes", "y":
		includeDisabled = true
	}
	users := s.users.List()
	if includeDisabled {
		users = s.users.ListAll()
	}
	if s.spec.SOCKS5 != nil && s.spec.SOCKS5.Enabled {
		users = append([]auth.User{{
			UUID:     auth.LegacySocksUserUUID,
			Name:     "Legacy SOCKS5",
			Kind:     "socks5",
			IsActive: true,
		}}, users...)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(users)
}

type patchUserReq struct {
	Name *string `json:"name"`
}

// handlePatchUser performs a partial update of a user. Currently only rename is supported.
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
	if id == auth.LegacySocksUserUUID {
		http.Error(w, "protected user", http.StatusConflict)
		return
	}
	var body patchUserReq
	if !s.decodeAdminJSON(w, r, &body) {
		return
	}
	if body.Name == nil {
		http.Error(w, "nothing to update", http.StatusBadRequest)
		return
	}
	u, err := s.users.RenameUser(id, *body.Name)
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
	if id == auth.LegacySocksUserUUID {
		http.Error(w, "protected user", http.StatusConflict)
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

// handlePurgeUser permanently deletes a user (and cascades all their stats).
// Distinct from soft-delete (DELETE /v1/users/{uuid}) which only flips is_active.
func (s *Server) handlePurgeUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	id := r.PathValue("uuid")
	if id == "" {
		http.Error(w, "uuid", http.StatusBadRequest)
		return
	}
	if id == auth.LegacySocksUserUUID {
		http.Error(w, "protected user", http.StatusConflict)
		return
	}
	if err := s.users.PurgeUser(id); err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.log.Error("purge user", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleEnableUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	id := r.PathValue("uuid")
	if id == "" {
		http.Error(w, "uuid", http.StatusBadRequest)
		return
	}
	if id == auth.LegacySocksUserUUID {
		http.Error(w, "protected user", http.StatusConflict)
		return
	}
	if err := s.users.EnableUser(id); err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.log.Error("enable user", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRotateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	id := r.PathValue("uuid")
	if id == "" {
		http.Error(w, "uuid", http.StatusBadRequest)
		return
	}
	if id == auth.LegacySocksUserUUID {
		http.Error(w, "protected user", http.StatusConflict)
		return
	}
	u, ok := s.users.Lookup(id)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if u.Kind == "socks5" {
		pass, err := s.users.RotateSocksPassword(id)
		if errors.Is(err, auth.ErrUserNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if err != nil {
			s.log.Error("rotate socks password", "err", err)
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		host := strings.TrimSpace(s.spec.PublicHost)
		if u.SocksPort == nil {
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		uri := config.Socks5ClientURI(host, *u.SocksPort, u.SocksUsername, pass)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"socks5_uri": uri, "password": pass})
		return
	}
	newUUID, err := s.users.RotateUUID(id)
	if errors.Is(err, auth.ErrUserNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if errors.Is(err, auth.ErrUnsupportedForKind) {
		http.Error(w, "unsupported for kind", http.StatusConflict)
		return
	}
	if err != nil {
		s.log.Error("rotate user UUID", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"uuid": newUUID})
}

// handleGetUserTraffic returns monthly traffic for a single user.
// Query param: ?month=YYYY-MM (default: current month).
func (s *Server) handleGetUserTraffic(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	if id == "" {
		http.Error(w, "uuid", http.StatusBadRequest)
		return
	}
	year, month := parseMonthParam(r)
	if id == auth.LegacySocksUserUUID {
		if s.spec.SOCKS5 == nil || !s.spec.SOCKS5.Enabled {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		now := time.Now()
		cy, cm, _ := now.Date()
		var total db.MonthlyTotal
		total.UserUUID = auth.LegacySocksUserUUID
		total.Year, total.Month = year, month
		if year == cy && int(cm) == month && s.statPeek != nil {
			tag := config.LegacyBridgeSOCKSInboundTag(s.spec)
			up := s.statPeek("inbound>>>" + tag + ">>>traffic>>>uplink")
			down := s.statPeek("inbound>>>" + tag + ">>>traffic>>>downlink")
			total.UplinkBytes, total.DownlinkBytes = up, down
			total.TotalBytes = up + down
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(total)
		return
	}
	if s.traffic == nil {
		http.Error(w, "traffic stats require database backend", http.StatusNotImplemented)
		return
	}
	if _, ok := s.users.Lookup(id); !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
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

// handleHealth probes bridge and exit connectivity (bridge process, tunnel, exit internet).
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	exitAddr := fmt.Sprintf("%s:%d", s.spec.Exit.Address, s.spec.Exit.Port)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	type nodeHealth struct {
		Reachable         bool  `json:"reachable"`
		InternetOK        bool  `json:"internet_ok"`
		InternetLatencyMS int64 `json:"internet_latency_ms,omitempty"`
		TunnelLatencyMS   int64 `json:"tunnel_latency_ms,omitempty"`
	}
	type healthResp struct {
		CheckedAt string     `json:"checked_at"`
		Bridge    nodeHealth `json:"bridge"`
		Exit      nodeHealth `json:"exit"`
	}
	res := healthResp{
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
		Bridge:    nodeHealth{Reachable: true},
	}

	var g errgroup.Group

	g.Go(func() error {
		rtt, err := probe.DialTCP(ctx, "1.1.1.1:443")
		if err != nil {
			return err
		}
		res.Bridge.InternetOK = true
		res.Bridge.InternetLatencyMS = rtt.Milliseconds()
		return nil
	})

	g.Go(func() error {
		rtt, err := probe.DialTCP(ctx, exitAddr)
		if err != nil {
			return err
		}
		res.Exit.Reachable = true
		res.Exit.TunnelLatencyMS = rtt.Milliseconds()
		return nil
	})

	g.Go(func() error {
		rtt, err := probe.DialTCP(ctx, config.HealthProbeListenIPPort)
		if err != nil {
			return err
		}
		res.Exit.InternetOK = true
		res.Exit.InternetLatencyMS = rtt.Milliseconds()
		return nil
	})

	_ = g.Wait()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
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
