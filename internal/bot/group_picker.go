package bot

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/db"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

type sharedGroup struct {
	RequestID int32 `json:"request_id"`
	ChatID    int64 `json:"chat_id"`
}

func (b *Bot) validateClosedGroup(ctx context.Context, id int64) (string, error) {
	var chat struct {
		Type     string `json:"type"`
		Title    string `json:"title"`
		Username string `json:"username"`
	}
	if id >= 0 || b.telegramJSON(ctx, "getChat", map[string]any{"chat_id": id}, &chat) != nil || (chat.Type != "group" && chat.Type != "supergroup") || chat.Username != "" {
		return "", errors.New("closed group unavailable")
	}
	var member struct {
		Status string `json:"status"`
	}
	if b.telegramJSON(ctx, "getChatMember", map[string]any{"chat_id": id, "user_id": b.api.Self.ID}, &member) != nil || member.Status != "administrator" {
		return "", errors.New("bot administrator required")
	}
	return chat.Title, nil
}
func (b *Bot) handleGroupShared(ctx context.Context, msg *tgbotapi.Message, shared sharedGroup) {
	allowed, e := b.adminRepo.IsAdmin(ctx, msg.From.ID)
	if e != nil || !allowed {
		return
	}
	b.picker.mu.Lock()
	p, ok := b.picker.pending[msg.From.ID]
	b.picker.mu.Unlock()
	if !ok || p.Kind != "group" || p.ID != shared.RequestID || time.Now().After(p.Expires) || shared.ChatID >= 0 {
		return
	}
	c, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	title, e := b.validateClosedGroup(c, shared.ChatID)
	if e != nil {
		b.reply(msg.Chat.ID, "Группа должна быть закрытой, а бот — её администратором. Проверьте права и выберите группу снова.")
		return
	}
	p.Target = shared.ChatID
	p.Title = title
	b.picker.mu.Lock()
	current, ok := b.picker.pending[msg.From.ID]
	if ok && current.ID == p.ID {
		b.picker.pending[msg.From.ID] = p
	}
	b.picker.mu.Unlock()
	if !ok || current.ID != p.ID {
		return
	}
	_ = b.telegramJSON(ctx, "sendMessage", map[string]any{"chat_id": msg.Chat.ID, "text": fmt.Sprintf("Разрешить регистрацию участникам группы «%s»? Уже выданный VPN-доступ сохранится, в том числе после выхода из группы.", title), "reply_markup": map[string]any{"inline_keyboard": [][]any{{map[string]any{"text": "Подключить эту группу", "callback_data": fmt.Sprintf("group_confirm:%d", p.ID)}}}}}, nil)
}
func (b *Bot) confirmGroupSelection(ctx context.Context, cb *tgbotapi.CallbackQuery) {
	id, e := strconv.ParseInt(strings.TrimPrefix(cb.Data, "group_confirm:"), 10, 32)
	if e != nil {
		return
	}
	b.picker.mu.Lock()
	p, ok := b.picker.pending[cb.From.ID]
	if ok && p.Kind == "group" && p.ID == int32(id) && p.Target < 0 && time.Now().Before(p.Expires) {
		delete(b.picker.pending, cb.From.ID)
	} else {
		ok = false
	}
	b.picker.mu.Unlock()
	if !ok {
		b.reply(cb.From.ID, "Выбор группы истёк. Откройте выбор заново.")
		return
	}
	c, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	title, e := b.validateClosedGroup(c, p.Target)
	if e != nil {
		b.reply(cb.From.ID, "Не удалось подтвердить группу и права бота. Повторите выбор.")
		return
	}
	var result db.VPNGroup
	_, e = b.relayJSON(c, "PUT", "/v1/enrollment/group", map[string]any{"chat_id": p.Target, "title": title, "enabled": true, "actor": cb.From.ID}, &result)
	if e != nil {
		b.reply(cb.From.ID, "Не удалось сохранить группу. Повторите выбор.")
		return
	}
	b.reply(cb.From.ID, "Группа подключена. Откройте «Приглашения» в Mini App, чтобы скопировать общую ссылку.")
}

func groupPickerRights() map[string]bool {
	return map[string]bool{"is_anonymous": false, "can_manage_chat": true, "can_delete_messages": false, "can_manage_video_chats": false, "can_restrict_members": false, "can_promote_members": false, "can_change_info": false, "can_invite_users": false, "can_post_stories": false, "can_edit_stories": false, "can_delete_stories": false}
}
