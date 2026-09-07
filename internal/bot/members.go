package bot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/db"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

type relayCloudError struct{ Code string }

func (e relayCloudError) Error() string { return "cloud operation unavailable" }

// relayJSON never returns upstream bodies or credential-bearing URLs in errors.
func (b *Bot) relayJSON(ctx context.Context, method, path string, input, output any) (int, error) {
	data, e := json.Marshal(input)
	if e != nil {
		return 0, e
	}
	req, e := http.NewRequestWithContext(ctx, method, b.adminAPIURL+path, bytes.NewReader(data))
	if e != nil {
		return 0, errors.New("relay unavailable")
	}
	req.Header.Set("Authorization", "Bearer "+b.adminAPIToken)
	req.Header.Set("Content-Type", "application/json")
	response, e := (&http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if e != nil {
		return 0, errors.New("relay unavailable")
	}
	defer response.Body.Close() //nolint:errcheck
	if response.StatusCode/100 != 2 {
		if strings.HasPrefix(path, "/v1/cloud/") {
			var detail struct {
				Code string `json:"code"`
			}
			if json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&detail) == nil && detail.Code != "" {
				return response.StatusCode, relayCloudError{Code: detail.Code}
			}
		}
		return response.StatusCode, errors.New("relay operation unavailable")
	}
	if output != nil {
		if e = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(output); e != nil {
			return 502, errors.New("invalid relay response")
		}
	}
	return response.StatusCode, nil
}
func (b *Bot) member(ctx context.Context, id int64) (db.Member, int, error) {
	var m db.Member
	status, e := b.relayJSON(ctx, "GET", fmt.Sprintf("/v1/members/%d", id), nil, &m)
	return m, status, e
}
func (b *Bot) telegramJSON(ctx context.Context, method string, input, output any) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
	}
	data, e := json.Marshal(input)
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", "https://api.telegram.org/bot"+b.botToken+"/"+method, bytes.NewReader(data))
	if e != nil {
		return errors.New("telegram unavailable")
	}
	req.Header.Set("Content-Type", "application/json")
	response, e := b.api.Client.Do(req)
	if e != nil {
		return errors.New("telegram unavailable")
	}
	defer response.Body.Close() //nolint:errcheck
	var envelope struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&envelope) != nil || !envelope.OK {
		return errors.New("telegram unavailable")
	}
	if output != nil {
		return json.Unmarshal(envelope.Result, output)
	}
	return nil
}
func allowedMember(status string, isMember bool) bool {
	switch status {
	case "creator", "administrator", "member":
		return true
	case "restricted":
		return isMember
	}
	return false
}
func (b *Bot) handleMemberStart(ctx context.Context, msg *tgbotapi.Message, token string) {
	if msg.Chat.Type != "private" || msg.From == nil {
		return
	}
	if _, status, e := b.member(ctx, msg.From.ID); e == nil {
		b.sendMemberButton(msg.Chat.ID)
		return
	} else if status != 404 {
		b.reply(msg.Chat.ID, "Сервис временно недоступен. Попробуйте ещё раз.")
		return
	}
	source := "invite"
	proof := strings.TrimPrefix(token, "vpn_i_")
	var chatID int64
	if strings.HasPrefix(token, "vpn_g_") {
		source = "group"
		proof = strings.TrimPrefix(token, "vpn_g_")
		var group db.VPNGroup
		if _, e := b.relayJSON(ctx, "GET", "/v1/enrollment/group", nil, &group); e != nil || !group.Enabled || group.Code != proof {
			b.reply(msg.Chat.ID, "Регистрация по этой ссылке недоступна.")
			return
		}
		chatID = group.ChatID
		var member struct {
			Status   string `json:"status"`
			IsMember bool   `json:"is_member"`
		}
		c, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		if e := b.telegramJSON(c, "getChatMember", map[string]any{"chat_id": chatID, "user_id": msg.From.ID}, &member); e != nil {
			b.reply(msg.Chat.ID, "Не удалось проверить участие в группе. Попробуйте ещё раз.")
			return
		}
		if !allowedMember(member.Status, member.IsMember) {
			b.reply(msg.Chat.ID, "Ссылка доступна только участникам разрешённой группы.")
			return
		}
	}
	var result db.Member
	_, e := b.relayJSON(ctx, "POST", "/v1/members/enroll", map[string]any{"telegram_id": msg.From.ID, "name": tgDisplayName(msg.From), "source": source, "token": proof, "chat_id": chatID}, &result)
	if e != nil {
		b.reply(msg.Chat.ID, "Приглашение недоступно или сервис временно не отвечает. Попробуйте ещё раз.")
		return
	}
	b.sendMemberButton(msg.Chat.ID)
}
func (b *Bot) sendMemberButton(chatID int64) {
	if b.miniAppURL == "" {
		b.reply(chatID, "Кабинет временно недоступен.")
		return
	}
	msg := tgbotapi.NewMessage(chatID, "Ваш личный кабинет Ultra:")
	msg.ReplyMarkup = webAppMarkup("Мой VPN", strings.TrimRight(b.miniAppURL, "/")+"/member")
	if _, e := b.api.Send(msg); e != nil {
		b.log.Warn("member button delivery failed")
	}
}
func (b *Bot) selfAuth(w http.ResponseWriter, r *http.Request) (TelegramUser, bool) {
	w.Header().Set("Cache-Control", "no-store")
	u, e := ValidateInitData(r.Header.Get(initDataHeader), b.botToken)
	if e != nil {
		http.Error(w, "invalid session", http.StatusUnauthorized)
		return u, false
	}
	return u, true
}
func (b *Bot) memberRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/enrollment/picker", b.pickerHTTP)
	mux.HandleFunc("POST /api/enrollment/group-picker", b.pickerHTTP)
	mux.HandleFunc("GET /member", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		page, _ := miniappFS.ReadFile("embed/miniapp/member.html")
		_, _ = w.Write(page)
	})
	mux.HandleFunc("GET /api/self", b.selfState)
	mux.HandleFunc("GET /api/self/traffic", b.selfTraffic)
	mux.HandleFunc("POST /api/self/subscription", b.selfSubscription)
	mux.HandleFunc("GET /api/self/exits", b.selfExits)
	mux.HandleFunc("PUT /api/self/exit-selection", b.selfExits)
	mux.HandleFunc("GET /api/enrollment/group", b.adminGroup)
	mux.HandleFunc("PUT /api/enrollment/group", b.adminGroup)
	mux.HandleFunc("GET /api/enrollment/invites", b.adminMemberInvites)
	mux.HandleFunc("POST /api/enrollment/invites", b.adminMemberInvites)
	mux.HandleFunc("POST /api/enrollment/invites/{id}/cancel", b.adminMemberInvites)
	mux.HandleFunc("GET /api/members", b.adminMembers)
	mux.HandleFunc("GET /api/members/traffic", b.adminMemberTraffic)
	mux.HandleFunc("GET /api/members/{id}/traffic", b.adminMemberTraffic)
	mux.HandleFunc("POST /api/members/{id}/action", b.adminMembers)
}
func memberHTTPError(w http.ResponseWriter, status int) {
	if status < 400 || status > 599 {
		status = 503
	}
	http.Error(w, "operation unavailable", status)
}
func (b *Bot) selfState(w http.ResponseWriter, r *http.Request) {
	u, ok := b.selfAuth(w, r)
	if !ok {
		return
	}
	admin, e := b.adminRepo.IsAdmin(r.Context(), u.ID)
	if e != nil {
		memberHTTPError(w, 503)
		return
	}
	m, status, e := b.member(r.Context(), u.ID)
	if status == 404 {
		jsonOK(w, map[string]any{"is_admin": admin, "registered": false, "name": u.DisplayName()})
		return
	}
	if e != nil {
		memberHTTPError(w, status)
		return
	}
	jsonOK(w, map[string]any{"is_admin": admin, "registered": true, "member": m})
}
func (b *Bot) selfSubscription(w http.ResponseWriter, r *http.Request) {
	u, ok := b.selfAuth(w, r)
	if !ok {
		return
	}
	var result struct {
		Token string `json:"token"`
	}
	status, e := b.relayJSON(r.Context(), "POST", fmt.Sprintf("/v1/members/%d/subscription", u.ID), nil, &result)
	if e != nil {
		memberHTTPError(w, status)
		return
	}
	base, e := url.Parse(b.miniAppURL)
	if e != nil || base.Scheme != "https" || base.Host == "" {
		memberHTTPError(w, 503)
		return
	}
	base.Path = "/sub/" + result.Token
	base.RawPath = ""
	base.RawQuery = ""
	base.Fragment = ""
	subscription := base.String()
	base.Path = "/happ"
	base.Fragment = result.Token
	jsonOK(w, map[string]string{"url": subscription, "import_url": base.String()})
}
func (b *Bot) selfExits(w http.ResponseWriter, r *http.Request) {
	u, ok := b.selfAuth(w, r)
	if !ok {
		return
	}
	m, status, e := b.member(r.Context(), u.ID)
	if e != nil {
		memberHTTPError(w, status)
		return
	}
	if !m.Active || m.Pending {
		memberHTTPError(w, 409)
		return
	}
	path := "/v1/client/users/" + m.UUID + "/exits"
	var input any
	if r.Method == "PUT" {
		var body struct {
			ExitID *string `json:"exit_id"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			memberHTTPError(w, 400)
			return
		}
		input = body
		path = "/v1/client/users/" + m.UUID + "/exit-selection"
	}
	var result json.RawMessage
	status, e = b.relayJSON(r.Context(), r.Method, path, input, &result)
	if e != nil {
		memberHTTPError(w, status)
		return
	}
	jsonOK(w, result)
}
func (b *Bot) adminMembers(w http.ResponseWriter, r *http.Request) {
	actor, ok := b.mustAdmin(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	path := "/v1/members"
	var input any
	if r.Method == "POST" {
		id, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if e != nil || id <= 0 {
			memberHTTPError(w, 400)
			return
		}
		var body struct {
			Action       string `json:"action"`
			ExpectedUUID string `json:"expected_uuid"`
			Actor        int64  `json:"actor"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			memberHTTPError(w, 400)
			return
		}
		body.Actor = actor.user.ID
		input = body
		path = fmt.Sprintf("/v1/members/%d/action", id)
	}
	var result json.RawMessage
	status, e := b.relayJSON(r.Context(), r.Method, path, input, &result)
	if e != nil {
		memberHTTPError(w, status)
		return
	}
	if r.Method == "GET" {
		var members []db.Member
		if json.Unmarshal(result, &members) != nil {
			memberHTTPError(w, 502)
			return
		}
		out := make([]memberView, 0, len(members))
		for _, m := range members {
			out = append(out, b.memberView(m))
		}
		jsonOK(w, out)
	} else {
		var m db.Member
		if json.Unmarshal(result, &m) != nil {
			memberHTTPError(w, 502)
			return
		}
		jsonOK(w, b.memberView(m))
	}
}
func (b *Bot) adminMemberInvites(w http.ResponseWriter, r *http.Request) {
	actor, ok := b.mustAdmin(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	path := "/v1/enrollment/invites"
	var input any
	if r.Method == "POST" {
		var body struct {
			Recipient int64 `json:"recipient"`
			Actor     int64 `json:"actor"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			memberHTTPError(w, 400)
			return
		}
		body.Actor = actor.user.ID
		input = body
		if r.PathValue("id") != "" {
			id, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
			if e != nil || id <= 0 {
				memberHTTPError(w, 400)
				return
			}
			path += fmt.Sprintf("/%d/cancel", id)
		}
	}
	var result json.RawMessage
	status, e := b.relayJSON(r.Context(), r.Method, path, input, &result)
	if e != nil {
		memberHTTPError(w, status)
		return
	}
	if r.Method == "POST" && r.PathValue("id") == "" {
		var v struct {
			Token string `json:"token"`
		}
		if json.Unmarshal(result, &v) != nil {
			memberHTTPError(w, 503)
			return
		}
		jsonOK(w, map[string]string{"url": "https://t.me/" + b.api.Self.UserName + "?start=vpn_i_" + v.Token})
		return
	}
	jsonOK(w, result)
}
func (b *Bot) adminGroup(w http.ResponseWriter, r *http.Request) {
	actor, ok := b.mustAdmin(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var group db.VPNGroup
	if r.Method == "PUT" {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if json.NewDecoder(r.Body).Decode(&group) != nil || group.ChatID >= 0 {
			memberHTTPError(w, 400)
			return
		}
		if group.Enabled {
			c, cancel := context.WithTimeout(r.Context(), 8*time.Second)
			defer cancel()
			title, err := b.validateClosedGroup(c, group.ChatID)
			if err != nil {
				http.Error(w, "closed group with bot administrator required", http.StatusBadRequest)
				return
			}
			group.Title = title
		}
		status, e := b.relayJSON(r.Context(), "PUT", "/v1/enrollment/group", struct {
			db.VPNGroup
			Actor int64 `json:"actor"`
		}{group, actor.user.ID}, &group)
		if e != nil {
			memberHTTPError(w, status)
			return
		}
	} else {
		status, e := b.relayJSON(r.Context(), "GET", "/v1/enrollment/group", nil, &group)
		if e != nil {
			memberHTTPError(w, status)
			return
		}
	}
	jsonOK(w, map[string]any{"chat_id": group.ChatID, "title": group.Title, "enabled": group.Enabled, "url": "https://t.me/" + b.api.Self.UserName + "?start=vpn_g_" + group.Code})
}

func (b *Bot) adminMemberTraffic(w http.ResponseWriter, r *http.Request) {
	if _, ok := b.mustAdmin(w, r); !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	path := "/v1/members/traffic"
	if raw := r.PathValue("id"); raw != "" {
		id, e := strconv.ParseInt(raw, 10, 64)
		if e != nil || id <= 0 {
			memberHTTPError(w, 400)
			return
		}
		path = fmt.Sprintf("/v1/members/%d/traffic", id)
	}
	var result json.RawMessage
	status, e := b.relayJSON(r.Context(), "GET", path, nil, &result)
	if e != nil {
		memberHTTPError(w, status)
		return
	}
	jsonOK(w, result)
}

// selfTraffic derives the owner only from validated Telegram initData.
// Disabled members retain access to their historical statistics.
func (b *Bot) selfTraffic(w http.ResponseWriter, r *http.Request) {
	u, ok := b.selfAuth(w, r)
	if !ok {
		return
	}
	if u.ID <= 0 {
		memberHTTPError(w, http.StatusUnauthorized)
		return
	}
	if _, status, e := b.member(r.Context(), u.ID); e != nil {
		memberHTTPError(w, status)
		return
	}
	var result json.RawMessage
	status, e := b.relayJSON(r.Context(), "GET", fmt.Sprintf("/v1/members/%d/traffic", u.ID), nil, &result)
	if e != nil {
		memberHTTPError(w, status)
		return
	}
	jsonOK(w, result)
}
