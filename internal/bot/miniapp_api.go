package bot

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"
)

//go:embed embed/miniapp
var miniappFS embed.FS

func (b *Bot) registerMiniAppRoutes(mux *http.ServeMux) {
	// Serve static frontend files embedded in the binary.
	sub, _ := fs.Sub(miniappFS, "embed/miniapp")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	// Mini App API — all routes require valid initData + admin status.
	mux.HandleFunc("GET /api/me", b.handleMe)
	mux.HandleFunc("GET /api/users", b.handleListUsers)
	mux.HandleFunc("POST /api/users", b.handleCreateUser)
	mux.HandleFunc("PATCH /api/users/{uuid}", b.handlePatchUser)
	mux.HandleFunc("DELETE /api/users/{uuid}", b.handleDeleteUser)
	mux.HandleFunc("POST /api/users/{uuid}/enable", b.handleEnableUser)
	mux.HandleFunc("POST /api/users/{uuid}/rotate", b.handleRotateUser)
	mux.HandleFunc("GET /api/users/{uuid}/config", b.handleGetUserConfig)
	mux.HandleFunc("GET /api/users/{uuid}/traffic", b.handleGetUserTraffic)
	mux.HandleFunc("GET /api/users/{uuid}/connections", b.handleUserConnections)
	mux.HandleFunc("GET /api/users/{uuid}/leak", b.handleUserLeak)
	mux.HandleFunc("GET /api/stats", b.handleStats)
	mux.HandleFunc("GET /api/stats/history", b.handleStatsHistory)
	mux.HandleFunc("GET /api/health", b.handleHealth)
	mux.HandleFunc("GET /api/diag/probe", b.handleDiagProbe)
	mux.HandleFunc("GET /api/diag/sessions", b.handleDiagSessions)
	mux.HandleFunc("GET /api/alerts/recent", b.handleRecentAlerts)
	mux.HandleFunc("POST /api/admin/invite", b.handleGenerateInvite)
	mux.HandleFunc("GET /api/admins", b.handleListAdmins)
	mux.HandleFunc("POST /api/admins/{telegram_id}/remove", b.handleRemoveAdmin)
	mux.HandleFunc("GET /api/audit/history", b.handleAuditHistory)
}

// ── auth middleware ────────────────────────────────────────────────────────────

// initDataHeader is the HTTP header carrying the raw Telegram WebApp initData string.
const initDataHeader = "X-Telegram-Init-Data"

type apiContext struct {
	user TelegramUser
}

func (b *Bot) mustAdmin(w http.ResponseWriter, r *http.Request) (apiContext, bool) {
	raw := r.Header.Get(initDataHeader)
	if raw == "" {
		http.Error(w, "missing initData", http.StatusUnauthorized)
		return apiContext{}, false
	}
	user, err := ValidateInitData(raw, b.botToken)
	if errors.Is(err, ErrExpiredInitData) {
		http.Error(w, "initData expired", http.StatusUnauthorized)
		return apiContext{}, false
	}
	if err != nil {
		http.Error(w, "invalid initData", http.StatusUnauthorized)
		return apiContext{}, false
	}
	isAdmin, err := b.adminRepo.IsAdmin(r.Context(), user.ID)
	if err != nil {
		b.log.Error("admin check", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return apiContext{}, false
	}
	if !isAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return apiContext{}, false
	}
	return apiContext{user: user}, true
}

// ── handlers ──────────────────────────────────────────────────────────────────

func (b *Bot) handleMe(w http.ResponseWriter, r *http.Request) {
	raw := r.Header.Get(initDataHeader)
	if raw == "" {
		http.Error(w, "missing initData", http.StatusUnauthorized)
		return
	}
	user, err := ValidateInitData(raw, b.botToken)
	if err != nil {
		http.Error(w, "invalid initData", http.StatusUnauthorized)
		return
	}
	isAdmin, err := b.adminRepo.IsAdmin(r.Context(), user.ID)
	if err != nil {
		b.log.Error("admin check in /api/me", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{
		"telegram_id": user.ID,
		"name":        user.DisplayName(),
		"username":    user.Username,
		"is_admin":    isAdmin,
	})
}

func (b *Bot) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := b.mustAdmin(w, r); !ok {
		return
	}
	// Fetch users, monthly traffic, and last-seen from the admin API.
	users, err := b.adminGet(r.Context(), "/v1/users?include_disabled=1")
	if err != nil {
		b.log.Error("admin GET /v1/users", "err", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	traffic, err := b.adminGet(r.Context(), "/v1/traffic/monthly")
	if err != nil {
		b.log.Error("admin GET /v1/traffic/monthly", "err", err)
		traffic = []byte("[]")
	}
	lastSeen, err := b.adminGet(r.Context(), "/v1/traffic/last-seen")
	if err != nil {
		b.log.Error("admin GET /v1/traffic/last-seen", "err", err)
		lastSeen = []byte("[]")
	}

	var userList []map[string]any
	if err := json.Unmarshal(users, &userList); err != nil {
		http.Error(w, "upstream parse error", http.StatusBadGateway)
		return
	}
	var trafficList []map[string]any
	_ = json.Unmarshal(traffic, &trafficList)
	var seenList []map[string]any
	_ = json.Unmarshal(lastSeen, &seenList)

	// Index traffic by UserUUID (admin API returns PascalCase field names).
	trafficByUUID := make(map[string]map[string]any, len(trafficList))
	for _, t := range trafficList {
		if uuid, ok := t["UserUUID"].(string); ok {
			trafficByUUID[uuid] = t
		}
	}
	// Index last-seen timestamp by UserUUID.
	seenByUUID := make(map[string]string, len(seenList))
	for _, s := range seenList {
		if uuid, ok := s["UserUUID"].(string); ok {
			if ts, ok := s["LastSeen"].(string); ok {
				seenByUUID[uuid] = ts
			}
		}
	}

	// Merge traffic and last-seen into user list.
	now := time.Now()
	year, month, _ := now.Date()
	for i, u := range userList {
		uuid, _ := u["uuid"].(string)
		t := trafficByUUID[uuid]
		var up, down, total float64
		if t != nil {
			up, _ = t["UplinkBytes"].(float64)
			down, _ = t["DownlinkBytes"].(float64)
			total = up + down
		}
		userList[i]["uplink_bytes"] = int64(up)
		userList[i]["downlink_bytes"] = int64(down)
		userList[i]["total_bytes"] = int64(total)
		userList[i]["stats_month"] = map[string]int{"year": year, "month": int(month)}
		userList[i]["last_seen_at"] = seenByUUID[uuid] // empty string if never seen
	}
	jsonOK(w, userList)
}

func (b *Bot) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	actx, ok := b.mustAdmin(w, r)
	if !ok {
		return
	}
	var body map[string]string
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(body["name"])
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	payload, _ := json.Marshal(map[string]string{"name": name})
	resp, err := b.adminPost(r.Context(), "/v1/users", payload)
	if err != nil {
		b.log.Error("admin POST /v1/users", "err", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(resp)
	b.auditAction(r.Context(), actx.user.ID, "user_create", nil, map[string]any{"name": name})
}

func (b *Bot) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	actx, ok := b.mustAdmin(w, r)
	if !ok {
		return
	}
	uuid := r.PathValue("uuid")
	if uuid == "" {
		http.Error(w, "uuid required", http.StatusBadRequest)
		return
	}
	if err := b.adminDelete(r.Context(), "/v1/users/"+uuid); err != nil {
		b.log.Error("admin DELETE /v1/users", "uuid", uuid, "err", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
	b.auditAction(r.Context(), actx.user.ID, "user_disable", &uuid, nil)
}

func (b *Bot) handleEnableUser(w http.ResponseWriter, r *http.Request) {
	actx, ok := b.mustAdmin(w, r)
	if !ok {
		return
	}
	uuid := r.PathValue("uuid")
	if uuid == "" {
		http.Error(w, "uuid required", http.StatusBadRequest)
		return
	}
	if _, err := b.adminPost(r.Context(), "/v1/users/"+uuid+"/enable", nil); err != nil {
		var apiErr *adminAPIError
		if errors.As(err, &apiErr) {
			http.Error(w, apiErr.body, apiErr.code)
			return
		}
		b.log.Error("admin POST /v1/users/{uuid}/enable", "uuid", uuid, "err", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
	b.auditAction(r.Context(), actx.user.ID, "user_enable", &uuid, nil)
}

func (b *Bot) handleRotateUser(w http.ResponseWriter, r *http.Request) {
	actx, ok := b.mustAdmin(w, r)
	if !ok {
		return
	}
	uuid := r.PathValue("uuid")
	if uuid == "" {
		http.Error(w, "uuid required", http.StatusBadRequest)
		return
	}
	resp, err := b.adminPost(r.Context(), "/v1/users/"+uuid+"/rotate", nil)
	if err != nil {
		var apiErr *adminAPIError
		if errors.As(err, &apiErr) {
			http.Error(w, apiErr.body, apiErr.code)
			return
		}
		b.log.Error("admin POST /v1/users/{uuid}/rotate", "uuid", uuid, "err", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(resp)
	b.auditAction(r.Context(), actx.user.ID, "user_rotate", &uuid, nil)
}

// handlePatchUser proxies partial-update to the admin API.
// Accepts JSON body {"name": "...", "note": "..."} — all fields optional.
func (b *Bot) handlePatchUser(w http.ResponseWriter, r *http.Request) {
	actx, ok := b.mustAdmin(w, r)
	if !ok {
		return
	}
	uuid := r.PathValue("uuid")
	if uuid == "" {
		http.Error(w, "uuid required", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	resp, err := b.adminPatch(r.Context(), "/v1/users/"+uuid, body)
	if err != nil {
		var apiErr *adminAPIError
		if errors.As(err, &apiErr) {
			http.Error(w, apiErr.body, apiErr.code)
			return
		}
		b.log.Error("admin PATCH /v1/users", "uuid", uuid, "err", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(resp)
	b.auditAction(r.Context(), actx.user.ID, "user_patch", &uuid, map[string]any{"body": string(body)})
}

// handleGetUserTraffic proxies the per-user monthly traffic endpoint.
// Accepts ?month=YYYY-MM (default: current month).
func (b *Bot) handleGetUserTraffic(w http.ResponseWriter, r *http.Request) {
	if _, ok := b.mustAdmin(w, r); !ok {
		return
	}
	uuid := r.PathValue("uuid")
	if uuid == "" {
		http.Error(w, "uuid required", http.StatusBadRequest)
		return
	}
	path := "/v1/users/" + uuid + "/traffic"
	if m := r.URL.Query().Get("month"); m != "" {
		path += "?month=" + m
	}
	resp, err := b.adminGet(r.Context(), path)
	if err != nil {
		b.log.Error("admin GET user traffic", "uuid", uuid, "err", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(resp)
}

func (b *Bot) handleUserConnections(w http.ResponseWriter, r *http.Request) {
	if _, ok := b.mustAdmin(w, r); !ok {
		return
	}
	if b.teleRepo == nil {
		http.Error(w, "db backend is disabled", http.StatusNotImplemented)
		return
	}
	uuid := r.PathValue("uuid")
	if uuid == "" {
		http.Error(w, "uuid required", http.StatusBadRequest)
		return
	}
	window, err := parseWindow(r.URL.Query().Get("window"))
	if err != nil {
		http.Error(w, "bad window", http.StatusBadRequest)
		return
	}
	bucket := r.URL.Query().Get("bucket")
	if bucket == "" {
		bucket = defaultBucketForWindow(window)
	}
	points, err := b.teleRepo.ConnectionsByBuckets(r.Context(), uuid, window, bucket)
	if err != nil {
		b.log.Error("load connection buckets", "uuid", uuid, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{
		"window": window.String(),
		"bucket": bucket,
		"points": points,
	})
}

func (b *Bot) handleUserLeak(w http.ResponseWriter, r *http.Request) {
	if _, ok := b.mustAdmin(w, r); !ok {
		return
	}
	if b.teleRepo == nil {
		http.Error(w, "db backend is disabled", http.StatusNotImplemented)
		return
	}
	uuid := r.PathValue("uuid")
	if uuid == "" {
		http.Error(w, "uuid required", http.StatusBadRequest)
		return
	}
	concurrent, err := b.teleRepo.CountConcurrentIPs(r.Context(), uuid, time.Minute)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	unique24h, err := b.teleRepo.CountUniqueIPs(r.Context(), uuid, 24*time.Hour)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	limit := 10
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, _ := strconv.Atoi(v); n > 0 && n <= 100 {
			limit = n
		}
	}
	signals, err := b.teleRepo.RecentUserLeakSignals(r.Context(), uuid, limit)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{
		"concurrent_ips": concurrent,
		"unique_ips_24h": unique24h,
		"signals":        signals,
		"suspicious":     concurrent > defaultLeakMaxConcurrent || unique24h > defaultLeakMaxUnique24h,
	})
}

// handleDiagProbe proxies a one-shot bridge↔exit TCP latency probe.
func (b *Bot) handleDiagProbe(w http.ResponseWriter, r *http.Request) {
	if _, ok := b.mustAdmin(w, r); !ok {
		return
	}
	resp, err := b.adminGet(r.Context(), "/v1/latency/probe")
	if err != nil {
		b.log.Error("admin GET /v1/latency/probe", "err", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(resp)
}

// handleDiagSessions proxies the recent per-connection latency traces.
// 501 from upstream is forwarded as-is so the UI can hint how to enable tracing.
func (b *Bot) handleDiagSessions(w http.ResponseWriter, r *http.Request) {
	if _, ok := b.mustAdmin(w, r); !ok {
		return
	}
	path := "/v1/latency/sessions"
	if l := r.URL.Query().Get("limit"); l != "" {
		path += "?limit=" + l
	}
	resp, err := b.adminGet(r.Context(), path)
	if err != nil {
		var apiErr *adminAPIError
		if errors.As(err, &apiErr) {
			http.Error(w, apiErr.body, apiErr.code)
			return
		}
		b.log.Error("admin GET /v1/latency/sessions", "err", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(resp)
}

func (b *Bot) handleGetUserConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := b.mustAdmin(w, r); !ok {
		return
	}
	uuid := r.PathValue("uuid")
	if uuid == "" {
		http.Error(w, "uuid required", http.StatusBadRequest)
		return
	}
	resp, err := b.adminGet(r.Context(), "/v1/users/"+uuid+"/client")
	if err != nil {
		b.log.Error("admin GET /client", "uuid", uuid, "err", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(resp)
}

func (b *Bot) handleStats(w http.ResponseWriter, r *http.Request) {
	if _, ok := b.mustAdmin(w, r); !ok {
		return
	}
	users, err := b.adminGet(r.Context(), "/v1/users")
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	traffic, err := b.adminGet(r.Context(), "/v1/traffic/monthly")
	if err != nil {
		traffic = []byte("[]")
	}

	var userList []map[string]any
	_ = json.Unmarshal(users, &userList)
	var trafficList []map[string]any
	_ = json.Unmarshal(traffic, &trafficList)

	var totalBytes float64
	for _, t := range trafficList {
		up, _ := t["UplinkBytes"].(float64)
		down, _ := t["DownlinkBytes"].(float64)
		totalBytes += up + down
	}
	now := time.Now()
	jsonOK(w, map[string]any{
		"total_users":       len(userList),
		"total_bytes_month": int64(totalBytes),
		"stats_month":       map[string]int{"year": now.Year(), "month": int(now.Month())},
	})
}

func (b *Bot) handleStatsHistory(w http.ResponseWriter, r *http.Request) {
	if _, ok := b.mustAdmin(w, r); !ok {
		return
	}
	path := "/v1/traffic/history"
	if m := r.URL.Query().Get("months"); m != "" {
		path += "?months=" + m
	}
	data, err := b.adminGet(r.Context(), path)
	if err != nil {
		b.log.Error("admin GET /v1/traffic/history", "err", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func (b *Bot) handleHealth(w http.ResponseWriter, r *http.Request) {
	if _, ok := b.mustAdmin(w, r); !ok {
		return
	}
	data, err := b.adminGet(r.Context(), "/v1/health")
	if err != nil {
		b.log.Error("admin GET /v1/health", "err", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func (b *Bot) handleGenerateInvite(w http.ResponseWriter, r *http.Request) {
	actx, ok := b.mustAdmin(w, r)
	if !ok {
		return
	}
	token, err := generateToken()
	if err != nil {
		b.log.Error("generate invite token", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := b.adminRepo.CreateInviteToken(r.Context(), token); err != nil {
		b.log.Error("store invite token", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"token": token})
	b.auditAction(r.Context(), actx.user.ID, "admin_invite_create", nil, nil)
}

func (b *Bot) handleRecentAlerts(w http.ResponseWriter, r *http.Request) {
	if _, ok := b.mustAdmin(w, r); !ok {
		return
	}
	if b.teleRepo == nil {
		http.Error(w, "notifications backend is disabled", http.StatusNotImplemented)
		return
	}
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}
	rows, err := b.teleRepo.RecentNotifications(r.Context(), limit)
	if err != nil {
		b.log.Error("recent alerts", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, rows)
}

func (b *Bot) handleListAdmins(w http.ResponseWriter, r *http.Request) {
	if _, ok := b.mustAdmin(w, r); !ok {
		return
	}
	admins, err := b.adminRepo.ListAdmins(r.Context())
	if err != nil {
		b.log.Error("list admins", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, admins)
}

func (b *Bot) handleRemoveAdmin(w http.ResponseWriter, r *http.Request) {
	actx, ok := b.mustAdmin(w, r)
	if !ok {
		return
	}
	idRaw := strings.TrimSpace(r.PathValue("telegram_id"))
	id, err := strconv.ParseInt(idRaw, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid telegram_id", http.StatusBadRequest)
		return
	}
	if id == actx.user.ID {
		http.Error(w, "cannot remove yourself", http.StatusBadRequest)
		return
	}
	admins, err := b.adminRepo.ListAdmins(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if len(admins) <= 1 {
		http.Error(w, "cannot remove last admin", http.StatusBadRequest)
		return
	}
	if err := b.adminRepo.RemoveAdmin(r.Context(), id); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	b.auditAction(r.Context(), actx.user.ID, "admin_remove", nil, map[string]any{"removed_telegram_id": id})
	w.WriteHeader(http.StatusNoContent)
}

func (b *Bot) handleAuditHistory(w http.ResponseWriter, r *http.Request) {
	if _, ok := b.mustAdmin(w, r); !ok {
		return
	}
	if b.teleRepo == nil {
		http.Error(w, "db backend is disabled", http.StatusNotImplemented)
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, _ := strconv.Atoi(v); n > 0 && n <= 200 {
			limit = n
		}
	}
	var tgID *int64
	if v := strings.TrimSpace(r.URL.Query().Get("telegram_id")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			tgID = &n
		}
	}
	action := strings.TrimSpace(r.URL.Query().Get("action"))
	rows, err := b.teleRepo.ListAdminAudit(r.Context(), limit, tgID, action)
	if err != nil {
		b.log.Error("audit history", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, rows)
}

// ── Admin API client helpers ──────────────────────────────────────────────────

var adminHTTPClient = &http.Client{Timeout: 15 * time.Second}

func (b *Bot) adminGet(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.adminAPIURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+b.adminAPIToken)
	resp, err := adminHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, &adminAPIError{code: resp.StatusCode, body: string(body)}
	}
	return body, nil
}

func (b *Bot) adminPost(ctx context.Context, path string, payload []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.adminAPIURL+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+b.adminAPIToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := adminHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, &adminAPIError{code: resp.StatusCode, body: string(body)}
	}
	return body, nil
}

func (b *Bot) adminPatch(ctx context.Context, path string, payload []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, b.adminAPIURL+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+b.adminAPIToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := adminHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, &adminAPIError{code: resp.StatusCode, body: string(body)}
	}
	return body, nil
}

func (b *Bot) adminDelete(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, b.adminAPIURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+b.adminAPIToken)
	resp, err := adminHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotFound {
		return &adminAPIError{code: resp.StatusCode}
	}
	return nil
}

type adminAPIError struct {
	code int
	body string
}

func (e *adminAPIError) Error() string {
	return "admin API returned " + http.StatusText(e.code) + ": " + e.body
}

// ── helpers ───────────────────────────────────────────────────────────────────

func (b *Bot) auditAction(
	ctx context.Context,
	telegramID int64,
	action string,
	targetUUID *string,
	payload map[string]any,
) {
	if b.teleRepo == nil {
		return
	}
	if err := b.teleRepo.LogAdminAction(ctx, telegramID, action, targetUUID, payload); err != nil {
		b.log.Warn("write admin audit log failed", "action", action, "err", err)
	}
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func parseWindow(s string) (time.Duration, error) {
	if s == "" {
		return 24 * time.Hour, nil
	}
	switch s {
	case "1h":
		return time.Hour, nil
	case "24h":
		return 24 * time.Hour, nil
	case "7d":
		return 7 * 24 * time.Hour, nil
	case "30d":
		return 30 * 24 * time.Hour, nil
	default:
		return 0, errors.New("unsupported window")
	}
}

func defaultBucketForWindow(window time.Duration) string {
	switch {
	case window <= 24*time.Hour:
		return "5m"
	case window <= 7*24*time.Hour:
		return "1h"
	case window <= 30*24*time.Hour:
		return "6h"
	default:
		return "1d"
	}
}
