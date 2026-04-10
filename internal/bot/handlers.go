package bot

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"github.com/NikitaDmitryuk/ultra/internal/db"
)

func (b *Bot) handleUpdate(ctx context.Context, update tgbotapi.Update) {
	if update.Message == nil {
		return
	}
	msg := update.Message
	if !msg.IsCommand() {
		return
	}
	switch msg.Command() {
	case "start":
		b.handleStart(ctx, msg)
	case "app":
		b.handleApp(ctx, msg)
	case "addadmin":
		b.handleAddAdmin(ctx, msg)
	case "help":
		b.handleHelp(ctx, msg)
	}
}

func (b *Bot) handleStart(ctx context.Context, msg *tgbotapi.Message) {
	token := strings.TrimSpace(msg.CommandArguments())
	if token == "" {
		b.handleApp(ctx, msg)
		return
	}
	// Consume invite token and register as admin.
	displayName := tgDisplayName(msg.From)
	err := b.adminRepo.ConsumeInviteToken(ctx, token, msg.From.ID, displayName)
	if errors.Is(err, db.ErrInvalidToken) {
		b.reply(msg.Chat.ID, "Токен недействителен или уже использован.")
		return
	}
	if err != nil {
		b.log.Error("consume invite token", "err", err)
		b.reply(msg.Chat.ID, "Внутренняя ошибка. Попробуйте позже.")
		return
	}
	b.reply(msg.Chat.ID,
		fmt.Sprintf("Добро пожаловать, %s! Вы зарегистрированы как администратор.", displayName),
	)
	b.sendAppButton(msg.Chat.ID)
}

func (b *Bot) handleApp(ctx context.Context, msg *tgbotapi.Message) {
	isAdmin, err := b.adminRepo.IsAdmin(ctx, msg.From.ID)
	if err != nil {
		b.log.Error("check admin", "err", err)
		b.reply(msg.Chat.ID, "Внутренняя ошибка.")
		return
	}
	if !isAdmin {
		b.reply(msg.Chat.ID, "Вы не являетесь администратором. Введите /start <токен> для регистрации.")
		return
	}
	b.sendAppButton(msg.Chat.ID)
}

func (b *Bot) handleAddAdmin(ctx context.Context, msg *tgbotapi.Message) {
	isAdmin, err := b.adminRepo.IsAdmin(ctx, msg.From.ID)
	if err != nil {
		b.log.Error("check admin", "err", err)
		b.reply(msg.Chat.ID, "Внутренняя ошибка.")
		return
	}
	if !isAdmin {
		b.reply(msg.Chat.ID, "Только администраторы могут приглашать новых администраторов.")
		return
	}

	token, err := generateToken()
	if err != nil {
		b.log.Error("generate token", "err", err)
		b.reply(msg.Chat.ID, "Не удалось сгенерировать токен.")
		return
	}
	if err := b.adminRepo.CreateInviteToken(ctx, token); err != nil {
		b.log.Error("store invite token", "err", err)
		b.reply(msg.Chat.ID, "Не удалось сохранить токен.")
		return
	}
	text := fmt.Sprintf(
		"Токен приглашения администратора:\n\n`/start %s`\n\nОднократного использования. Передайте в личку новому администратору.",
		token,
	)
	out := tgbotapi.NewMessage(msg.Chat.ID, text)
	out.ParseMode = "Markdown"
	if _, err := b.api.Send(out); err != nil {
		b.log.Error("send message", "err", err)
	}
}

func (b *Bot) handleHelp(_ context.Context, msg *tgbotapi.Message) {
	text := "Команды:\n" +
		"/app — открыть панель управления\n" +
		"/addadmin — выдать приглашение нового администратора\n" +
		"/help — эта справка\n\n" +
		"Управление доступно через Mini App."
	b.reply(msg.Chat.ID, text)
}

// webAppMarkup produces an inline keyboard with a single WebApp button.
// The go-telegram-bot-api/v5 library predates WebApp buttons; we serialise
// the JSON directly using an anonymous struct.
func webAppMarkup(label, url string) any {
	type webAppInfo struct {
		URL string `json:"url"`
	}
	type button struct {
		Text   string     `json:"text"`
		WebApp webAppInfo `json:"web_app"`
	}
	return struct {
		InlineKeyboard [][]button `json:"inline_keyboard"`
	}{
		InlineKeyboard: [][]button{{{Text: label, WebApp: webAppInfo{URL: url}}}},
	}
}

func (b *Bot) sendAppButton(chatID int64) {
	if b.miniAppURL == "" {
		b.reply(chatID, "Mini App URL не настроен. Обратитесь к оператору.")
		return
	}
	msg := tgbotapi.NewMessage(chatID, "Панель управления Ultra:")
	msg.ReplyMarkup = webAppMarkup("Открыть панель управления", b.miniAppURL)
	if _, err := b.api.Send(msg); err != nil {
		b.log.Error("send app button", "err", err)
	}
}

func (b *Bot) reply(chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	if _, err := b.api.Send(msg); err != nil {
		b.log.Error("send reply", "err", err)
	}
}

func tgDisplayName(u *tgbotapi.User) string {
	if u == nil {
		return "unknown"
	}
	name := strings.TrimSpace(u.FirstName + " " + u.LastName)
	if name != "" {
		return name
	}
	if u.UserName != "" {
		return "@" + u.UserName
	}
	return fmt.Sprintf("id%d", u.ID)
}

func generateToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
