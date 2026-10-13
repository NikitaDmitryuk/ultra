package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/adminapi"
	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/NikitaDmitryuk/ultra/internal/proxy"
	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
	"github.com/NikitaDmitryuk/ultra/internal/stats"
	"github.com/NikitaDmitryuk/ultra/internal/subscriptionkey"
)

const runtimeLease = 24 * time.Hour

// PersistedUser explicitly includes private routing fields omitted from public API JSON.
// This DTO and the payload containing it must only be stored in the private state DB.
type persistedUser struct {
	ServiceTargets []string               `json:"service_targets,omitempty"`
	User           auth.User              `json:"user"`
	AccountID      string                 `json:"account_id"`
	Routes         []auth.RouteCredential `json:"routes"`
	Exclusions     []string               `json:"exclusions"`
	Reasons        map[string]string      `json:"reasons"`
	Fallback       string                 `json:"fallback"`
}
type runtimeSnapshotV1 struct {
	Version     int                       `json:"version"`
	Fingerprint string                    `json:"fingerprint"`
	Users       []persistedUser           `json:"users"`
	Nodes       []exits.Node              `json:"nodes"`
	Limits      []runtimestate.QuotaLimit `json:"limits"`
}

func snapshotUsers(users []auth.User) []persistedUser {
	out := make([]persistedUser, 0, len(users))
	for _, u := range users {
		out = append(out, persistedUser{ServiceTargets: u.ServiceTargets, User: u, AccountID: u.AccountID, Routes: u.Routes, Exclusions: u.ExcludedExitIDs, Reasons: u.ExitExclusionReasons, Fallback: u.FallbackExitID})
	}
	return out
}
func (s runtimeSnapshotV1) users() []auth.User {
	out := make([]auth.User, 0, len(s.Users))
	for _, p := range s.Users {
		u := p.User
		u.AccountID = p.AccountID
		u.ServiceTargets = p.ServiceTargets
		u.Routes = p.Routes
		u.ExcludedExitIDs = p.Exclusions
		u.ExitExclusionReasons = p.Reasons
		u.FallbackExitID = p.Fallback
		out = append(out, u)
	}
	return out
}
func runtimeFingerprint(spec *config.Spec) string {
	// The entire spec is conservative: even a non-routing edit requires a fresh DB
	// confirmation. Credentials are hashed, never exposed in diagnostics.
	data, _ := json.Marshal(spec)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func decodeRuntimeSnapshot(snapshot runtimestate.Snapshot, fingerprint string, now time.Time) (runtimeSnapshotV1, error) {
	var p runtimeSnapshotV1
	if snapshot.ConfirmedAt.IsZero() || snapshot.ConfirmedAt.After(now.Add(time.Minute)) || !now.Before(snapshot.ConfirmedAt.Add(runtimeLease)) {
		return p, errors.New("runtime snapshot expired or invalid clock")
	}
	if err := json.Unmarshal(snapshot.Payload, &p); err != nil {
		return p, errors.New("runtime snapshot corrupt")
	}
	if (p.Version != 1 && p.Version != 2) || p.Fingerprint != fingerprint {
		return p, errors.New("runtime snapshot incompatible")
	}
	return p, nil
}

type runtimeRunner interface {
	ValidateJSON([]byte) error
	ConfigureAccounting(*runtimestate.Store, []auth.User) error
	ReloadReason([]byte, string) error
	Status() proxy.ReloadStatus
	Close() error
}

type bridgeRuntime struct {
	mu              sync.RWMutex
	applyMu         sync.Mutex // local work only; never held across PostgreSQL/network calls
	refreshMu       sync.Mutex
	users           []auth.User
	nodes           []exits.Node
	confirmed       time.Time
	revision        uint64
	appliedRevision uint64
	online          bool
	cacheOnly       bool
	lastError       string
	fault           bool
	limits          []runtimestate.QuotaLimit
	saveSnapshot    func(runtimestate.Snapshot, []runtimestate.QuotaLimit) error
	lastApplied     []auth.User
	lastNodes       []exits.Node
	lastActive      string
	state           *runtimestate.Store
	runner          runtimeRunner
	spec            *config.Spec
	strategy        mimic.Strategy
	logLevel        string
	selector        *exits.Selector
	applications    *auth.RouteApplications
	collector       *stats.Collector
	log             *slog.Logger
	now             func() time.Time
}

func (r *bridgeRuntime) List() []auth.User {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]auth.User(nil), r.users...)
}
func (r *bridgeRuntime) ListAll() []auth.User { return r.List() }
func (r *bridgeRuntime) Nodes() []exits.Node {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]exits.Node(nil), r.nodes...)
}
func (r *bridgeRuntime) status() any {
	r.mu.RLock()
	defer r.mu.RUnlock()
	mode := "autonomous"
	if r.cacheOnly {
		mode = "cache_only"
	}
	if r.online {
		mode = "online"
	}
	if r.fault || r.confirmed.IsZero() || !r.now().Before(r.confirmed.Add(runtimeLease)) {
		mode = "closed"
	}
	status := map[string]any{"mode": mode, "revision": r.revision, "applied_revision": r.appliedRevision, "confirmed_at": r.confirmed, "expires_at": r.confirmed.Add(runtimeLease), "error": r.lastError}
	status["control_disabled"] = r.cacheOnly
	status["backup"] = recoveryStatus("/var/lib/ultra-relay/recovery-status.json", r.now())
	if r.state != nil {
		count, bytes, oldest, err := r.state.PendingStats()
		status["traffic_queue"] = map[string]any{"batches": count, "bytes": bytes, "oldest_at": oldest, "ready": err == nil}
	}
	return status
}

// Read only the public operational receipt, never the private backup configuration.
func recoveryStatus(path string, now time.Time) map[string]any {
	result := map[string]any{"ready": false, "independent": false}
	f, err := os.Open(path)
	if err != nil {
		result["error"] = "receipt_unavailable"
		return result
	}
	defer func() { _ = f.Close() }()
	var receipt struct {
		SnapshotAt  int64 `json:"snapshot_at"`
		CompletedAt int64 `json:"completed_at"`
		Independent bool  `json:"independent"`
	}
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 || json.Unmarshal(data, &receipt) != nil || receipt.SnapshotAt <= 0 || receipt.CompletedAt < receipt.SnapshotAt || receipt.CompletedAt > now.Add(time.Minute).Unix() {
		result["error"] = "receipt_invalid"
		return result
	}
	age := now.Unix() - receipt.SnapshotAt
	result["snapshot_at"] = time.Unix(receipt.SnapshotAt, 0).UTC()
	result["completed_at"] = time.Unix(receipt.CompletedAt, 0).UTC()
	result["age_seconds"] = age
	result["independent"] = receipt.Independent
	result["ready"] = age >= 0 && age <= 300
	if age < 0 || age > 300 {
		result["error"] = "receipt_stale_or_invalid_clock"
	}
	return result
}
func (r *bridgeRuntime) setError(code string) {
	r.mu.Lock()
	r.lastError = code
	r.online = false
	r.mu.Unlock()
}
func (r *bridgeRuntime) apply(reason string, force bool) error {
	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	return r.applyLocked(reason, force)
}
func (r *bridgeRuntime) applyLocked(reason string, force bool) (err error) {
	r.mu.RLock()
	users := append([]auth.User(nil), r.users...)
	nodes := append([]exits.Node(nil), r.nodes...)
	confirmed := r.confirmed
	fault := r.fault
	r.mu.RUnlock()
	if fault || confirmed.IsZero() || !r.now().Before(confirmed.Add(runtimeLease)) || confirmed.After(r.now().Add(time.Minute)) {
		_ = r.runner.Close()
		r.mu.Lock()
		r.appliedRevision = 0
		r.mu.Unlock()
		r.lastApplied = nil
		r.applications.Finish(errors.New("runtime snapshot expired"))
		return errors.New("runtime snapshot expired")
	}
	// Clone each slice: cached authoritative exclusions must not be changed by a
	// temporary local budget exhaustion or health observation.
	for i := range users {
		users[i].ExcludedExitIDs = append([]string(nil), users[i].ExcludedExitIDs...)
		for _, n := range nodes {
			left, e := r.state.Remaining(users[i].AccountID, n.ID)
			if e != nil || left <= 0 {
				users[i].ExcludedExitIDs = append(users[i].ExcludedExitIDs, n.ID)
			}
		}
	}
	enabled := exits.FilterEnabled(nodes)
	active := r.selector.ActiveID()
	found := false
	for _, n := range enabled {
		if n.ID == active {
			found = true
			break
		}
	}
	if !found {
		n, _ := exits.SelectActive(enabled, nil)
		active = n.ID
		r.selector.SetActiveID(active)
	}
	users = auth.ExpandRoutes(users)
	users = applyEffectiveUserExits(users, enabled, active, r.selector.HealthSnapshot())
	if !force && reflect.DeepEqual(users, r.lastApplied) && reflect.DeepEqual(nodes, r.lastNodes) && active == r.lastActive && r.runner.Status().Error == "" {
		r.applications.Begin(users)
		r.applications.Finish(nil)
		r.mu.Lock()
		r.appliedRevision = r.revision
		r.mu.Unlock()
		return nil
	}
	r.applications.Begin(users)
	defer func() { r.applications.Finish(err) }()
	data, err := config.BuildBridgeXRayJSON(r.spec, users, nodes, active, r.strategy, r.logLevel)
	if err != nil {
		return err
	}
	if err = r.runner.ReloadReason(data, reason); err != nil {
		return err
	}
	r.lastApplied = users
	r.lastNodes = nodes
	r.lastActive = active
	r.mu.Lock()
	r.appliedRevision = r.revision
	r.mu.Unlock()
	return nil
}

// refresh performs control work outside applyMu. Local failover is never waiting
// for a database retry or provider API request.
func (r *bridgeRuntime) refresh(ctx context.Context, database *db.DB, users *auth.DBManager, nodes *exits.Manager) error {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	c, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := database.Pool.Ping(c); err != nil {
		return err
	}
	r.mu.RLock()
	recovering := !r.online
	r.mu.RUnlock()
	checkpoint := r.collector.Checkpoint
	if recovering {
		checkpoint = r.collector.CheckpointFull
	}
	if err := checkpoint(c); err != nil {
		return err
	}
	if err := r.collector.Replay(c); err != nil {
		return err
	}
	quotas := db.NewQuotaRepo(database)
	routes := db.NewRouteRepo(database)
	if _, err := quotas.Recalculate(c, r.now()); err != nil {
		return err
	}
	if err := routes.PrepareManual(c); err != nil {
		return err
	}
	if err := users.Refresh(c); err != nil {
		return err
	}
	if err := nodes.Refresh(c); err != nil {
		return err
	}
	all := users.ListAll()
	live := make([]auth.User, 0, len(all))
	for _, u := range all {
		if u.IsActive && (u.Kind == "" || u.Kind == "vless") {
			live = append(live, u)
		}
	}
	limits, err := quotas.RuntimeLimits(c, r.now())
	if err != nil {
		return err
	}
	acknowledgements, err := quotas.Snapshot(c)
	if err != nil {
		return err
	}
	now := r.now().UTC()
	for i := range limits {
		until := now.Add(runtimeLease)
		if limits[i].ExpiresAt.IsZero() || limits[i].ExpiresAt.After(until) {
			limits[i].ExpiresAt = until
		}
	}
	payload := runtimeSnapshotV1{Version: 1, Fingerprint: runtimeFingerprint(r.spec), Users: snapshotUsers(live), Nodes: nodes.List(), Limits: limits}
	for _, user := range live {
		if len(user.ServiceTargets) > 0 {
			payload.Version = 2
			break
		}
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	err = r.commitCandidate(payload, now, data)

	if err != nil {
		r.setError("runtime_apply_failed")
		return err
	}
	if err = quotas.Acknowledge(c, acknowledgements); err != nil {
		return err
	}
	return routes.AppliedManual(c)
}

// commitCandidate holds only the local apply lock. Failed preparation restores
// the previous authorization and never extends its lease. A persistence failure
// restores the previous configuration without extending its authorization.
func (r *bridgeRuntime) commitCandidate(payload runtimeSnapshotV1, now time.Time, data []byte) (err error) {
	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	r.mu.RLock()
	oldUsers, oldNodes, oldLimits, oldConfirmed, oldRevision := r.users, r.nodes, r.limits, r.confirmed, r.revision
	r.mu.RUnlock()
	live := payload.users()
	validationUsers := applyEffectiveUserExits(auth.ExpandRoutes(live), exits.FilterEnabled(payload.Nodes), r.selector.ActiveID(), r.selector.HealthSnapshot())
	validationConfig, validationErr := config.BuildBridgeXRayJSON(r.spec, validationUsers, payload.Nodes, r.selector.ActiveID(), r.strategy, r.logLevel)
	if validationErr != nil {
		return validationErr
	}
	if validationErr = r.runner.ValidateJSON(validationConfig); validationErr != nil {
		return validationErr
	}
	var oldSnapshot *runtimestate.Snapshot
	if previous, loadErr := r.state.LoadSnapshot(); loadErr == nil {
		oldSnapshot = &previous
	} else if !errors.Is(loadErr, runtimestate.ErrNoSnapshot) {
		return loadErr
	}
	persisted := false
	defer func() {
		if err != nil && !persisted {
			r.applications.Finish(err)
		}
		if err != nil && persisted {
			restoreLimits := r.state.RestoreSnapshot(oldSnapshot, oldLimits)
			restoreMeter := r.runner.ConfigureAccounting(r.state, oldUsers)
			r.mu.Lock()
			r.users = oldUsers
			r.nodes = oldNodes
			r.limits = oldLimits
			r.confirmed = oldConfirmed
			r.revision = oldRevision
			r.fault = restoreLimits != nil || restoreMeter != nil
			if restoreLimits != nil || restoreMeter != nil {
				r.fault = true
			}
			closed := r.fault
			r.mu.Unlock()
			if closed {
				_ = r.runner.Close()
				r.lastApplied = nil
			} else if rollbackErr := r.applyLocked("restore durable authorization", true); rollbackErr != nil {
				r.mu.Lock()
				r.fault = true
				r.mu.Unlock()
				_ = r.runner.Close()
				r.lastApplied = nil
			}
			r.applications.Finish(err)
		}
	}()
	save := r.saveSnapshot
	if save == nil {
		save = r.state.SaveSnapshot
	}
	// Persist the complete confirmed candidate first. A crash between this write
	// and reload replays it at startup; no running access depends on unsaved state.
	if err = save(runtimestate.Snapshot{Revision: oldRevision + 1, ConfirmedAt: now, Payload: data}, payload.Limits); err != nil {
		return err
	}
	persisted = true
	if err = r.runner.ConfigureAccounting(r.state, live); err != nil {
		return err
	}
	r.mu.Lock()
	r.users = live
	r.nodes = payload.Nodes
	r.limits = payload.Limits
	r.confirmed = now
	r.fault = false
	r.mu.Unlock()
	if err = r.applyLocked("confirmed database state", false); err != nil {
		return err
	}
	r.mu.Lock()
	r.online = true
	r.lastError = ""
	r.revision = oldRevision + 1
	r.appliedRevision = r.revision
	r.mu.Unlock()
	return nil
}

// The listener is present while the control database is unavailable. It exposes
// no credentials and rejects mutations until the full authenticated API is ready.
type runtimeHTTP struct {
	mu      sync.RWMutex
	next    http.Handler
	token   [32]byte
	runtime *bridgeRuntime
}

func (h *runtimeHTTP) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.mu.RLock()
	next := h.next
	h.mu.RUnlock()
	if next != nil {
		next.ServeHTTP(w, req)
		return
	}
	token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	sum := sha256.Sum256([]byte(token))
	if !strings.HasPrefix(req.Header.Get("Authorization"), "Bearer ") || subtle.ConstantTimeCompare(sum[:], h.token[:]) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if req.Method == "GET" && (req.URL.Path == "/v1/health" || req.URL.Path == "/v1/hardening") {
		_ = json.NewEncoder(w).Encode(map[string]any{"runtime": h.runtime.status(), "reload": h.runtime.runner.Status(), "control_ready": false})
		return
	}
	w.Header().Set("Retry-After", "10")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(`{"error":"control_unavailable"}`))
}
func (h *runtimeHTTP) install(next http.Handler) { h.mu.Lock(); h.next = next; h.mu.Unlock() }

type bridgeOptions struct {
	CacheOnly     bool
	probeInterval time.Duration // Private test hook; CLI keeps the production interval.
}

type bridgeHostRunner interface {
	runtimeRunner
	stats.XrayInstance
	DrainAccountTraffic() map[string]map[string][2]int64
	ProbeExit(context.Context, exits.Node, []string) exits.Health
}

func runBridge(ctx context.Context, spec *config.Spec, specPath, statePath, token string, runner bridgeHostRunner, strategy mimic.Strategy, xrayLog string, log *slog.Logger, options ...bridgeOptions) error {
	var opts bridgeOptions
	if len(options) != 0 {
		opts = options[0]
	}
	if spec.Database == nil || spec.Database.DSN == "" {
		return errors.New("bridge database configuration required")
	}
	if spec.SplitRoutingEnabled() {
		if err := os.Setenv("XRAY_LOCATION_ASSET", spec.GeoAssetsDir); err != nil {
			return err
		}
	}
	if opts.CacheOnly {
		info, err := os.Lstat(statePath)
		if err != nil || !info.Mode().IsRegular() || info.Size() < 4096 {
			log.Error("emergency state unavailable; VPN closed", "code", "state_unavailable")
			return runClosedDiagnostics(ctx, spec.AdminListen, token, runner, true)
		}
	}
	state, err := runtimestate.Open(statePath)
	if err != nil {
		log.Error("private runtime state unavailable; VPN closed", "code", "state_unavailable")
		return runClosedDiagnostics(ctx, spec.AdminListen, token, runner, opts.CacheOnly)
	}
	defer func() { _ = state.Close() }()
	r := &bridgeRuntime{state: state, runner: runner, spec: spec, strategy: strategy, logLevel: xrayLog, log: log, now: time.Now, applications: &auth.RouteApplications{}, cacheOnly: opts.CacheOnly}
	r.selector = exits.NewSelector(func(c context.Context, n exits.Node) exits.Health {
		return runner.ProbeExit(c, n, spec.HealthTargets())
	})
	if cached, e := state.LoadSnapshot(); e == nil {
		if p, e := decodeRuntimeSnapshot(cached, runtimeFingerprint(spec), r.now()); e == nil {
			r.users = p.users()
			r.nodes = p.Nodes
			r.limits = p.Limits
			r.confirmed = cached.ConfirmedAt
			r.revision = cached.Revision
			if e = runner.ConfigureAccounting(state, r.users); e != nil {
				return e
			}
			if e = r.apply("autonomous startup", true); e != nil {
				log.Warn("cached runtime unavailable", "code", "cached_apply_failed")
				r.fault = true
				r.lastError = "cached_apply_failed"
			}
		} else {
			r.lastError = "snapshot_unusable"
		}
	}
	r.collector = stats.NewDurable(runner, nil, r, state, log)
	r.collector.Start()
	defer r.collector.Close()
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	listenerFailure := make(chan error, 1)
	handler := &runtimeHTTP{token: sha256.Sum256([]byte(token)), runtime: r}
	if token != "" {
		host, _, e := net.SplitHostPort(spec.AdminListen)
		if e != nil || (host != "127.0.0.1" && host != "localhost") {
			return errors.New("admin listener must be loopback")
		}
		listener, e := net.Listen("tcp", spec.AdminListen)
		if e != nil {
			return e
		}
		server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
		defer func() { _ = server.Close() }()
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := server.Serve(listener); e != nil && !errors.Is(e, http.ErrServerClosed) {
				log.Error("admin listener failed", "code", "admin_listener_failed")
				listenerFailure <- errors.New("admin listener failed")
				cancel()
			}
		}()
		go func() { <-child.Done(); _ = server.Close() }()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		interval := opts.probeInterval
		if interval <= 0 {
			interval = 10 * time.Second
		}
		r.selector.RunWorker(child, interval, func(context.Context) ([]exits.Node, error) { return exits.FilterEnabled(r.Nodes()), nil }, func() {
			if e := r.apply("exit health selection", false); e != nil {
				r.setError("route_apply_failed")
			}
		})
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-child.Done():
				return
			case <-ticker.C:
				if e := r.apply("local quota or lease", false); e != nil {
					r.setError("runtime_unavailable")
				}
			}
		}
	}()
	if !opts.CacheOnly {
		wg.Add(1)
		go func() { defer wg.Done(); r.control(child, &wg, handler, specPath, token) }()
	}
	<-child.Done()
	cancel()
	wg.Wait()
	_ = runner.Close()
	select {
	case e := <-listenerFailure:
		return e
	default:
	}
	return nil
}

// Never replace an unreadable accounting DB with an empty one: doing so would
// forgive durable charges. Keep only authenticated diagnostics available.
func runClosedDiagnostics(ctx context.Context, listen, token string, runner runtimeRunner, cacheOnly ...bool) error {
	_ = runner.Close()
	if token == "" {
		<-ctx.Done()
		return nil
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil || (host != "127.0.0.1" && host != "localhost") {
		return errors.New("admin listener must be loopback")
	}
	r := &bridgeRuntime{runner: runner, fault: true, lastError: "state_unavailable", now: time.Now}
	if len(cacheOnly) != 0 {
		r.cacheOnly = cacheOnly[0]
	}
	h := &runtimeHTTP{token: sha256.Sum256([]byte(token)), runtime: r}
	server := &http.Server{Addr: listen, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("closed diagnostic listener: %w", err)
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-done:
		}
	}()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (r *bridgeRuntime) control(ctx context.Context, wg *sync.WaitGroup, handler *runtimeHTTP, specPath, token string) {
	var database *db.DB
	for ctx.Err() == nil {
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		d, err := db.Open(c, r.spec.Database.DSN)
		cancel()
		if err == nil {
			database = d
			break
		}
		r.setError("database_unavailable")
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}
	}
	if database == nil {
		return
	}
	defer database.Close()
	userRepo := db.NewUserRepo(database)
	exitRepo := db.NewExitNodeRepo(database)
	var users *auth.DBManager
	var nodes *exits.Manager
	// Initialization can fail after a successful ping; retry it without stopping
	// the autonomous dataplane or accidentally starting duplicate cloud workers.
	for ctx.Err() == nil {
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := exitRepo.Bootstrap(c, r.spec, filepath.Join(filepath.Dir(specPath), exits.BootstrapFileName))
		if err == nil {
			users, err = auth.NewDBManagerContext(c, userRepo, nil, r.log)
		}
		if err == nil {
			nodes, err = exits.NewManagerContext(c, exitRepo, nil, r.log)
		}
		cancel()
		if err == nil {
			break
		}
		r.setError("database_initialization_failed")
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}
	}
	if ctx.Err() != nil {
		return
	}
	refresh := func(c context.Context) error {
		err := r.refresh(c, database, users, nodes)
		if err != nil {
			r.setError("database_refresh_failed")
		}
		return err
	}
	users.ApplyChange = func([]auth.User) error { return refresh(ctx) }
	nodes.SetOnChange(func([]exits.Node) {
		if err := refresh(ctx); err != nil {
			r.log.Warn("exit application pending", "code", "route_apply_failed")
		}
	})
	traffic := db.NewTrafficRepo(database)
	r.collector.SetTrafficDB(traffic)
	if token != "" {
		srv, err := adminapi.NewServer(r.spec.AdminListen, token, users, traffic, r.spec, nodes, r.selector, nil, r.log, nil)
		if err != nil {
			r.setError("admin_initialization_failed")
			return
		}
		srv.ReloadStatus = r.runner.Status
		srv.RouteStatus = r.applications.Status
		srv.RuntimeStatus = r.status
		configureCloud(ctx, wg, srv, database, r.spec, nodes, refresh, users.Refresh, r.log)
		keys, keyErr := subscriptionkey.Load(os.Getenv("ULTRA_SUBSCRIPTION_ENCRYPTION_KEY_FILE"))
		if keyErr != nil {
			r.log.Warn("subscription recovery and issuance unavailable: encryption key not configured")
		}
		subscriptions := db.NewSubscriptionRepo(database, keys)
		srv.Subscriptions = subscriptions
		srv.Members = &adminapi.MemberService{Repo: db.NewMemberRepo(database), Subscriptions: subscriptions, Apply: refresh}
		wg.Add(1)
		go func() { defer wg.Done(); srv.Members.Run(ctx) }()
		handler.install(srv.Handler())
	}
	if r.spec.SplitRoutingEnabled() {
		registerSplitRoutingUSR1(r.log, func([]auth.User) { _ = r.apply("geo assets reload", true) }, users)
	}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		if err := refresh(ctx); err != nil {
			r.log.Warn("runtime refresh unavailable; retaining last confirmed state", "code", "runtime_refresh_failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
