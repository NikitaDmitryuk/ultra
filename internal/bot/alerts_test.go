package bot

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"github.com/NikitaDmitryuk/ultra/internal/db"
)

type fakeAlertsTele struct {
	mu     sync.Mutex
	next   int64
	rows   []db.Notification
	states map[string]db.AlertState
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

func (f *fakeAlertsTele) GetAlertState(_ context.Context, dedupeKey string) (db.AlertState, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.states == nil {
		return db.AlertState{}, false, nil
	}
	s, ok := f.states[dedupeKey]
	return s, ok, nil
}

func (f *fakeAlertsTele) UpsertAlertState(_ context.Context, s db.AlertState) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.states == nil {
		f.states = map[string]db.AlertState{}
	}
	f.states[s.DedupeKey] = s
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
		{"exit_failover", "Active exit переключена на резервную."},
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

func TestExitDownDebounceRequiresThreeFailedProbes(t *testing.T) {
	tele := &fakeAlertsTele{}
	adm := &fakeAdminLister{admins: []db.BotAdmin{{TelegramID: 1}}}
	reachable := true
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"active_exit_id":"exit-a","exit":{"id":"exit-a","name":"primary","reachable":%t}}`, reachable)
	}))
	defer ts.Close()
	b := &Bot{adminRepo: adm, alertsTele: tele, adminAPIURL: ts.URL}
	var st exitAlertState

	b.probeExitAlerts(context.Background(), &st)
	reachable = false
	b.probeExitAlerts(context.Background(), &st)
	b.probeExitAlerts(context.Background(), &st)
	if len(tele.rows) != 0 {
		t.Fatalf("expected no alert before third failed probe, got %d", len(tele.rows))
	}
	b.probeExitAlerts(context.Background(), &st)
	if len(tele.rows) != 1 || tele.rows[0].Type != "exit_down" {
		t.Fatalf("expected one exit_down alert, got %#v", tele.rows)
	}
	b.probeExitAlerts(context.Background(), &st)
	if len(tele.rows) != 1 {
		t.Fatalf("expected no duplicate exit_down alert, got %d", len(tele.rows))
	}
}

func TestExitUpDebounceRequiresTwoSuccessfulProbes(t *testing.T) {
	tele := &fakeAlertsTele{}
	adm := &fakeAdminLister{admins: []db.BotAdmin{{TelegramID: 1}}}
	reachable := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"active_exit_id":"exit-a","exit":{"id":"exit-a","name":"primary","reachable":%t}}`, reachable)
	}))
	defer ts.Close()
	b := &Bot{adminRepo: adm, alertsTele: tele, adminAPIURL: ts.URL}
	st := exitAlertState{initialized: true, activeID: "exit-a", reachable: false}

	reachable = true
	b.probeExitAlerts(context.Background(), &st)
	if len(tele.rows) != 0 {
		t.Fatalf("expected no alert before second successful probe, got %d", len(tele.rows))
	}
	b.probeExitAlerts(context.Background(), &st)
	if len(tele.rows) != 1 || tele.rows[0].Type != "exit_up" {
		t.Fatalf("expected one exit_up alert, got %#v", tele.rows)
	}
}

func TestExitUpDebounceUsesPersistentDownStateAfterRestart(t *testing.T) {
	tele := &fakeAlertsTele{states: map[string]db.AlertState{
		exitHealthStateKey("exit-a"): {
			DedupeKey: exitHealthStateKey("exit-a"),
			Type:      "exit_health",
			Severity:  alertSeverityCritical,
			Channel:   alertChannelMiniApp,
			Status:    "down",
		},
	}}
	adm := &fakeAdminLister{admins: []db.BotAdmin{{TelegramID: 1}}}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"active_exit_id":"exit-a","exit":{"id":"exit-a","name":"primary","reachable":true}}`)
	}))
	defer ts.Close()
	b := &Bot{adminRepo: adm, alertsTele: tele, adminAPIURL: ts.URL}
	var st exitAlertState

	b.probeExitAlerts(context.Background(), &st)
	if len(tele.rows) != 0 {
		t.Fatalf("expected no exit_up before second successful probe, got %#v", tele.rows)
	}
	b.probeExitAlerts(context.Background(), &st)
	if len(tele.rows) != 1 || tele.rows[0].Type != "exit_up" {
		t.Fatalf("expected one exit_up from persisted down state, got %#v", tele.rows)
	}
}

func TestExitDownDebounceUsesPersistentFailureStreakAfterRestart(t *testing.T) {
	tele := &fakeAlertsTele{states: map[string]db.AlertState{
		exitHealthStateKey("exit-a"): {
			DedupeKey:           exitHealthStateKey("exit-a"),
			Type:                "exit_health",
			Severity:            alertSeverityInfo,
			Channel:             alertChannelMiniApp,
			Status:              "up",
			ConsecutiveFailures: exitDownConfirmSamples - 1,
		},
	}}
	adm := &fakeAdminLister{admins: []db.BotAdmin{{TelegramID: 1}}}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"active_exit_id":"exit-a","exit":{"id":"exit-a","name":"primary","reachable":false}}`)
	}))
	defer ts.Close()
	b := &Bot{adminRepo: adm, alertsTele: tele, adminAPIURL: ts.URL}
	var st exitAlertState

	b.probeExitAlerts(context.Background(), &st)
	if len(tele.rows) != 1 || tele.rows[0].Type != "exit_down" {
		t.Fatalf("expected one exit_down from persisted failure streak, got %#v", tele.rows)
	}
}

func TestAlertStateCooldownSkipsRecentMatchingNotification(t *testing.T) {
	tele := &fakeAlertsTele{}
	adm := &fakeAdminLister{admins: []db.BotAdmin{{TelegramID: 1}}}
	b := &Bot{adminRepo: adm, alertsTele: tele}
	ctx := context.Background()

	ev := alertEvent{
		DedupeKey: "token_leak.strong:u1:unique_ips_window",
		Type:      "token_leak",
		Severity:  alertSeverityCritical,
		Channel:   alertChannelTelegram,
		Payload:   map[string]any{"text": "x", "user_uuid": "u1", "kind": "unique_ips_window"},
		Cooldown:  time.Hour,
	}
	b.emitAlert(ctx, ev)
	b.emitAlert(ctx, ev)

	if len(tele.rows) != 1 {
		t.Fatalf("expected cooldown to keep one notification, got %d", len(tele.rows))
	}
}
