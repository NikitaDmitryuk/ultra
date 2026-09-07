package bot

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/db"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

type memberPicker struct {
	mu      sync.Mutex
	pending map[int64]pickerRequest
}
type pickerRequest struct {
	Kind    string
	Title   string
	ID      int32
	Target  int64
	Expires time.Time
}

func (b *Bot) startPicker(ctx context.Context, id int64) error {
	return b.startPickerKind(ctx, id, "user")
}
func (b *Bot) startPickerKind(ctx context.Context, id int64, kind string) error {
	var random [4]byte
	if _, e := rand.Read(random[:]); e != nil {
		return e
	}
	requestID := int32(binary.LittleEndian.Uint32(random[:]) & 0x7fffffff)
	b.picker.mu.Lock()
	if b.picker.pending == nil {
		b.picker.pending = map[int64]pickerRequest{}
	}
	for owner, p := range b.picker.pending {
		if time.Now().After(p.Expires) {
			delete(b.picker.pending, owner)
		}
	}
	b.picker.pending[id] = pickerRequest{Kind: kind, ID: requestID, Expires: time.Now().Add(10 * time.Minute)}
	b.picker.mu.Unlock()
	if kind == "group" {
		return b.telegramJSON(ctx, "sendMessage", map[string]any{"chat_id": id, "text": "Выберите закрытую группу, где вы и бот — администраторы. Если её нет в списке, сначала добавьте бота администратором. После выбора подтвердите включение регистрации.", "reply_markup": map[string]any{"keyboard": [][]any{{map[string]any{"text": "Выбрать закрытую группу", "request_chat": map[string]any{"request_id": requestID, "chat_is_channel": false, "chat_has_username": false, "bot_is_member": true, "user_administrator_rights": groupPickerRights(), "bot_administrator_rights": groupPickerRights(), "request_title": true}}}}, "resize_keyboard": true, "one_time_keyboard": true}}, nil)
	}
	return b.telegramJSON(ctx, "sendMessage", map[string]any{"chat_id": id, "text": "Выберите получателя VPN-приглашения. Затем подтвердите выдачу. Для числового ID: /invitevpn 123456789", "reply_markup": map[string]any{"keyboard": [][]any{{map[string]any{"text": "Выбрать получателя", "request_users": map[string]any{"request_id": requestID, "user_is_bot": false, "max_quantity": 1, "request_name": true}}}}, "resize_keyboard": true, "one_time_keyboard": true}}, nil)
}
func (b *Bot) pickerHTTP(w http.ResponseWriter, r *http.Request) {
	actor, ok := b.mustAdmin(w, r)
	if !ok {
		return
	}
	kind := "user"
	if r.URL.Path == "/api/enrollment/group-picker" {
		kind = "group"
	}
	if e := b.startPickerKind(r.Context(), actor.user.ID, kind); e != nil {
		memberHTTPError(w, 503)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonOK(w, map[string]bool{"sent": true})
}
func (b *Bot) inviteVPNCommand(ctx context.Context, msg *tgbotapi.Message) {
	allowed, e := b.adminRepo.IsAdmin(ctx, msg.From.ID)
	if e != nil || !allowed {
		b.reply(msg.Chat.ID, "Только администратор может выдавать приглашения.")
		return
	}
	target := strings.TrimSpace(msg.CommandArguments())
	if target == "" {
		if e = b.startPicker(ctx, msg.From.ID); e != nil {
			b.reply(msg.Chat.ID, "Не удалось открыть выбор. Попробуйте ещё раз.")
		}
		return
	}
	id, e := strconv.ParseInt(target, 10, 64)
	if e != nil || id <= 0 {
		b.reply(msg.Chat.ID, "Укажите положительный числовой Telegram ID.")
		return
	}
	var random [4]byte
	if _, e = rand.Read(random[:]); e != nil {
		return
	}
	request := pickerRequest{ID: int32(binary.LittleEndian.Uint32(random[:]) & 0x7fffffff), Target: id, Expires: time.Now().Add(10 * time.Minute)}
	b.picker.mu.Lock()
	if b.picker.pending == nil {
		b.picker.pending = map[int64]pickerRequest{}
	}
	b.picker.pending[msg.From.ID] = request
	b.picker.mu.Unlock()
	b.confirmPicker(ctx, msg.From.ID, request)
}
func (b *Bot) confirmPicker(ctx context.Context, actor int64, p pickerRequest) {
	_ = b.telegramJSON(ctx, "sendMessage", map[string]any{"chat_id": actor, "text": fmt.Sprintf("Выдать VPN-приглашение %s (Telegram ID %d)? Срок — 7 дней, только для этого аккаунта. Административных прав оно не даёт.", p.Title, p.Target), "reply_markup": map[string]any{"inline_keyboard": [][]any{{map[string]any{"text": "Выдать приглашение", "callback_data": fmt.Sprintf("vpn_confirm:%d", p.ID)}}}}}, nil)
}
func (b *Bot) handleMemberCallback(ctx context.Context, cb *tgbotapi.CallbackQuery) {
	if cb.From == nil || cb.Message == nil || cb.Message.Chat == nil || cb.Message.Chat.Type != "private" {
		return
	}
	admin, e := b.adminRepo.IsAdmin(ctx, cb.From.ID)
	if e != nil || !admin {
		return
	}
	_ = b.telegramJSON(ctx, "answerCallbackQuery", map[string]any{"callback_query_id": cb.ID}, nil)
	if strings.HasPrefix(cb.Data, "vpn_disable:") {
		id, e := strconv.ParseInt(strings.TrimPrefix(cb.Data, "vpn_disable:"), 10, 64)
		if e != nil || id <= 0 {
			return
		}
		var m db.Member
		_, e = b.relayJSON(ctx, "POST", fmt.Sprintf("/v1/members/%d/action", id), map[string]any{"action": "disable", "actor": cb.From.ID}, &m)
		if e != nil {
			b.reply(cb.From.ID, "Не удалось отключить доступ. Повторите действие.")
		} else if m.Pending {
			b.reply(cb.From.ID, "Отключение сохранено, ожидаем применения на сервере.")
		} else {
			b.reply(cb.From.ID, "VPN-доступ отключён.")
		}
		return
	}
	if strings.HasPrefix(cb.Data, "group_confirm:") {
		b.confirmGroupSelection(ctx, cb)
		return
	}
	if !strings.HasPrefix(cb.Data, "vpn_confirm:") {
		return
	}
	requestID, e := strconv.ParseInt(strings.TrimPrefix(cb.Data, "vpn_confirm:"), 10, 32)
	if e != nil {
		return
	}
	b.picker.mu.Lock()
	p, ok := b.picker.pending[cb.From.ID]
	if ok && p.Kind != "group" && p.ID == int32(requestID) && p.Target > 0 && time.Now().Before(p.Expires) {
		delete(b.picker.pending, cb.From.ID)
	} else {
		ok = false
	}
	b.picker.mu.Unlock()
	if !ok {
		b.reply(cb.From.ID, "Подтверждение истекло или уже использовано. Выберите получателя заново.")
		return
	}
	var result struct {
		Token string `json:"token"`
	}
	_, e = b.relayJSON(ctx, "POST", "/v1/enrollment/invites", map[string]any{"recipient": p.Target, "actor": cb.From.ID, "recipient_name": p.Title}, &result)
	if e != nil {
		b.reply(cb.From.ID, "Не удалось выдать приглашение. Повторите выбор получателя.")
		return
	}
	b.reply(cb.From.ID, fmt.Sprintf("Приглашение для Telegram ID %d, действует 7 дней:\nhttps://t.me/%s?start=vpn_i_%s", p.Target, b.api.Self.UserName, result.Token))
}

// Decode new Telegram fields not yet supported by the pinned bot library.
type memberUpdate struct {
	ID       int                     `json:"update_id"`
	Message  json.RawMessage         `json:"message"`
	Callback *tgbotapi.CallbackQuery `json:"callback_query"`
}

func (b *Bot) runMemberPolling(ctx context.Context) error {
	offset := 0
	for ctx.Err() == nil {
		var updates []memberUpdate
		c, cancel := context.WithTimeout(ctx, 35*time.Second)
		e := b.telegramJSON(c, "getUpdates", map[string]any{"offset": offset, "timeout": 25, "allowed_updates": []string{"message", "callback_query"}}, &updates)
		cancel()
		if e != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(3 * time.Second):
				continue
			}
		}
		for _, update := range updates {
			if update.ID >= offset {
				offset = update.ID + 1
			}
			if update.Callback != nil {
				b.handleMemberCallback(ctx, update.Callback)
				continue
			}
			if len(update.Message) == 0 {
				continue
			}
			var msg tgbotapi.Message
			if json.Unmarshal(update.Message, &msg) != nil || msg.Chat == nil || msg.Chat.Type != "private" || msg.From == nil {
				continue
			}
			var extra struct {
				Chat   *sharedGroup `json:"chat_shared"`
				Shared *struct {
					RequestID int32 `json:"request_id"`
					Users     []struct {
						ID        int64  `json:"user_id"`
						FirstName string `json:"first_name"`
						LastName  string `json:"last_name"`
					} `json:"users"`
				} `json:"users_shared"`
			}
			if json.Unmarshal(update.Message, &extra) != nil {
				continue
			}
			if extra.Chat != nil {
				b.handleGroupShared(ctx, &msg, *extra.Chat)
				continue
			}
			if extra.Shared != nil {
				allowed, e := b.adminRepo.IsAdmin(ctx, msg.From.ID)
				if e != nil || !allowed || len(extra.Shared.Users) != 1 || extra.Shared.Users[0].ID <= 0 {
					continue
				}
				b.picker.mu.Lock()
				p, ok := b.picker.pending[msg.From.ID]
				if ok && p.Kind != "group" && p.ID == extra.Shared.RequestID && time.Now().Before(p.Expires) {
					p.Target = extra.Shared.Users[0].ID
					p.Title = strings.TrimSpace(extra.Shared.Users[0].FirstName + " " + extra.Shared.Users[0].LastName)
					b.picker.pending[msg.From.ID] = p
				} else {
					ok = false
				}
				b.picker.mu.Unlock()
				if ok {
					b.confirmPicker(ctx, msg.From.ID, p)
				}
				continue
			}
			b.handleUpdate(ctx, tgbotapi.Update{UpdateID: update.ID, Message: &msg})
		}
	}
	return ctx.Err()
}
func (b *Bot) memberNotifications(ctx context.Context) {
	if b.teleRepo == nil {
		return
	}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c, cancel := context.WithTimeout(ctx, 8*time.Second)
			items, e := b.teleRepo.ClaimMemberNotifications(c)
			if e == nil {
				for _, n := range items {
					allowed, err := b.adminRepo.IsAdmin(c, n.AdminID)
					if err != nil {
						continue
					}
					if !allowed {
						_ = b.teleRepo.MemberNotificationSent(c, n.MemberID, n.AdminID)
						continue
					}
					e = b.telegramJSON(c, "sendMessage", map[string]any{"chat_id": n.AdminID, "text": fmt.Sprintf("Новый VPN-пользователь: %s\nTelegram ID: %d\nСпособ регистрации: %s", n.Name, n.MemberID, n.Source), "reply_markup": map[string]any{"inline_keyboard": [][]any{{map[string]any{"text": "Отключить VPN-доступ", "callback_data": fmt.Sprintf("vpn_disable:%d", n.MemberID)}}}}}, nil)
					if e == nil {
						_ = b.teleRepo.MemberNotificationSent(c, n.MemberID, n.AdminID)
					}
				}
			}
			cancel()
		}
	}
}
