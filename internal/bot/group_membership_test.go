package bot

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/db"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

type groupTransport func(*http.Request) (*http.Response, error)

func (f groupTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestMembershipChecksAreCachedAndDoNotChangeAccess(t *testing.T) {
	groupID := int64(-123)
	calls := 0
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("membership must not mutate access")
		}
		switch r.URL.Path {
		case "/v1/enrollment/group":
			_ = json.NewEncoder(w).Encode(db.VPNGroup{ChatID: groupID})
		case "/v1/members":
			_ = json.NewEncoder(w).Encode([]db.Member{{TelegramID: 123, Active: true}})
		default:
			t.Error("unexpected path")
		}
	}))
	defer relay.Close()
	response := `{"ok":true,"result":{"status":"left"}}`
	client := &http.Client{Transport: groupTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(response)), Header: http.Header{}}, nil
	})}
	b := &Bot{adminAPIURL: relay.URL, api: &tgbotapi.BotAPI{Client: client}}
	b.refreshGroupMembership(context.Background())
	m := b.memberView(db.Member{TelegramID: 123, Active: true})
	if m.Group.State != "outside" || !m.Active || m.Group.CheckedAt == nil {
		t.Fatal("membership affected permission or lost provenance")
	}
	b.refreshGroupMembership(context.Background())
	if calls != 1 {
		t.Fatal("cache ignored")
	}
	groupID = -456
	response = `{"ok":false}`
	b.refreshGroupMembership(context.Background())
	if b.memberView(db.Member{TelegramID: 123}).Group.State != "unknown" {
		t.Fatal("Telegram failure claimed absence")
	}
	b.memberships.Lock()
	old := time.Now().Add(-10 * time.Minute)
	b.memberships.items[123] = membershipStatus{State: "inside", CheckedAt: &old}
	b.memberships.Unlock()
	if b.memberView(db.Member{TelegramID: 123}).Group.State != "unknown" {
		t.Fatal("stale membership shown as current")
	}
}
func TestNativeGroupPickerUsesPrivateGroupCriteria(t *testing.T) {
	var request map[string]any
	client := &http.Client{Transport: groupTransport(func(r *http.Request) (*http.Response, error) {
		_ = json.NewDecoder(r.Body).Decode(&request)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true,"result":{}}`)), Header: http.Header{}}, nil
	})}
	b := &Bot{api: &tgbotapi.BotAPI{Client: client}}
	if e := b.startPickerKind(context.Background(), 123, "group"); e != nil {
		t.Fatal(e)
	}
	keyboard := request["reply_markup"].(map[string]any)["keyboard"].([]any)
	criteria := keyboard[0].([]any)[0].(map[string]any)["request_chat"].(map[string]any)
	if criteria["chat_is_channel"] != false || criteria["chat_has_username"] != false || criteria["bot_is_member"] != true {
		t.Fatal("unsafe picker criteria")
	}
	if b.picker.pending[123].Kind != "group" {
		t.Fatal("group selection mixed with user invite")
	}
}
