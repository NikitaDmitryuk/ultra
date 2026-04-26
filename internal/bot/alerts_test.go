package bot

import (
	"context"
	"sync"
	"testing"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"github.com/NikitaDmitryuk/ultra/internal/db"
)

type fakeAlertsTele struct {
	mu   sync.Mutex
	next int64
	rows []db.Notification
}

func (f *fakeAlertsTele) EnqueueNotification(_ context.Context, n db.Notification) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	n.ID = f.next
	if n.CreatedAt.IsZero() {
		n.CreatedAt = time.Now()
	}
	f.rows = append(f.rows, n)
	return nil
}

func (f *fakeAlertsTele) PendingNotifications(_ context.Context, limit int) ([]db.Notification, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []db.Notification
	for _, n := range f.rows {
		if n.SentAt != nil {
			continue
		}
		out = append(out, n)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (f *fakeAlertsTele) MarkNotificationSent(_ context.Context, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	for i := range f.rows {
		if f.rows[i].ID == id {
			f.rows[i].SentAt = &now
			return nil
		}
	}
	return nil
}

type fakeAdminLister struct {
	admins []db.BotAdmin
}

func (f *fakeAdminLister) IsAdmin(context.Context, int64) (bool, error) { return true, nil }
func (f *fakeAdminLister) ConsumeInviteToken(context.Context, string, int64, string) error {
	return nil
}
func (f *fakeAdminLister) CreateInviteToken(context.Context, string) error { return nil }
func (f *fakeAdminLister) ListAdmins(context.Context) ([]db.BotAdmin, error) {
	return f.admins, nil
}
func (f *fakeAdminLister) RemoveAdmin(context.Context, int64) error { return nil }

type fakeMsgSender struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (f *fakeMsgSender) Send(tgbotapi.Chattable) (tgbotapi.Message, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return tgbotapi.Message{}, f.err
}

func TestEnqueueAdminAlertCreatesPerAdmin(t *testing.T) {
	tele := &fakeAlertsTele{}
	adm := &fakeAdminLister{admins: []db.BotAdmin{{TelegramID: 1}, {TelegramID: 2}}}
	b := &Bot{adminRepo: adm, alertsTele: tele}

	b.enqueueAdminAlert(context.Background(), "test_alert", map[string]any{"text": "hi"})
	if len(tele.rows) != 2 {
		t.Fatalf("expected 2 queued notifications, got %d", len(tele.rows))
	}
}

func TestFlushOutboxOnceMarksSent(t *testing.T) {
	tele := &fakeAlertsTele{}
	sender := &fakeMsgSender{}
	b := &Bot{alertsTele: tele, msgSender: sender}

	_ = tele.EnqueueNotification(context.Background(), db.Notification{
		TelegramID: 77,
		Type:       "test_alert",
		Payload:    map[string]any{"text": "x"},
	})

	b.flushOutboxOnce(context.Background())
	if sender.calls != 1 {
		t.Fatalf("expected 1 send, got %d", sender.calls)
	}
	if tele.rows[0].SentAt == nil {
		t.Fatalf("expected notification marked sent")
	}
}

func TestFormatNotificationTextKnownTypes(t *testing.T) {
	cases := []struct {
		typ  string
		want string
	}{
		{"exit_down", "Exit-нода недоступна."},
		{"exit_up", "Exit-нода снова доступна."},
		{"traffic_spike", "Обнаружен резкий рост трафика."},
		{"token_leak", "Обнаружена подозрительная активность по токену."},
		{"test_alert", "Тестовое уведомление от Mini App."},
		{"unknown_type", "Новое событие мониторинга."},
	}
	for _, tc := range cases {
		got := formatNotificationText(db.Notification{Type: tc.typ})
		if got != tc.want {
			t.Fatalf("type %q: got %q want %q", tc.typ, got, tc.want)
		}
	}
}
