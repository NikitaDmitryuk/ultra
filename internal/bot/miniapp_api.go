package bot

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
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
	mux.HandleFunc("DELETE /api/users/{uuid}", b.handleDeleteUser)
	mux.HandleFunc("GET /api/users/{uuid}/config", b.handleGetUserConfig)
	mux.HandleFunc("GET /api/stats", b.handleStats)
	mux.HandleFunc("POST /api/admin/invite", b.handleGenerateInvite)
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
	// Fetch users and monthly traffic from the admin API.
	users, err := b.adminGet(r.Context(), "/v1/users")
	if err != nil {
		b.log.Error("admin GET /v1/users", "err", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	traffic, err := b.adminGet(r.Context(), "/v1/traffic/monthly")
	if err != nil {
		b.log.Error("admin GET /v1/traffic/monthly", "err", err)
		// Non-fatal: return users without traffic stats.
		traffic = []byte("[]")
	}

	var userList []map[string]any
	if err := json.Unmarshal(users, &userList); err != nil {
		http.Error(w, "upstream parse error", http.StatusBadGateway)
		return
	}
	var trafficList []map[string]any
	_ = json.Unmarshal(traffic, &trafficList)

	// Index traffic by UserUUID (admin API returns PascalCase field names).
	trafficByUUID := make(map[string]map[string]any, len(trafficList))
	for _, t := range trafficList {
		if uuid, ok := t["UserUUID"].(string); ok {
			trafficByUUID[uuid] = t
		}
	}

	// Merge traffic into user list.
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
	}
	jsonOK(w, userList)
}

func (b *Bot) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if _, ok := b.mustAdmin(w, r); !ok {
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
}

func (b *Bot) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if _, ok := b.mustAdmin(w, r); !ok {
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

func (b *Bot) handleGenerateInvite(w http.ResponseWriter, r *http.Request) {
	if _, ok := b.mustAdmin(w, r); !ok {
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

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
