package bot

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/db"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

func TestPersonalNotificationSelfOnlyStrictPreferences(t *testing.T) {
	calls := 0
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/v1/members/123/notifications" {
			t.Error("request selected another owner", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"credentials":false,"access":false,"quota":false,"availability":false}`))
	}))
	defer relay.Close()
	b := &Bot{botToken: "synthetic", adminAPIURL: relay.URL}
	for _, tc := range []struct {
		body string
		auth bool
		want int
	}{
		{`{"credentials":false,"access":false,"quota":false,"availability":false}`, true, 200},
		{`{"credentials":true}`, true, 400},
		{`{"credentials":false,"access":false,"quota":false,"availability":false,"telegram_id":999}`, true, 400},
		{`{"credentials":null,"access":false,"quota":false,"availability":false}`, true, 400},
		{`{"credentials":false,"access":false,"quota":false,"availability":false} {}`, true, 400},
		{`{}`, false, 401},
	} {
		r := httptest.NewRequest("PUT", "/api/self/notifications?telegram_id=999", strings.NewReader(tc.body))
		if tc.auth {
			r.Header.Set(initDataHeader, signedInitData(t, b.botToken, 123))
		}
		w := httptest.NewRecorder()
		b.selfNotifications(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s status %d", tc.body, w.Code)
		}
	}
	if calls != 1 {
		t.Fatal("invalid request reached relay", calls)
	}
}
func TestPersonalNotificationDeliveryCurrentTokenBlockedAndRecheck(t *testing.T) {
	for _, scenario := range []string{"success", "blocked", "optout", "upstream-error", "pending-confirmation", "rate-limit"} {
		t.Run(scenario, func(t *testing.T) {
			prepares, sends, completed := 0, 0, false
			n := db.PersonalNotification{
				ID:         7,
				Account:    "account",
				Category:   "credentials",
				Kind:       "uuid",
				Revision:   3,
				Attempts:   1,
				TelegramID: 123,
			}
			relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/personal-notifications/claim":
					_ = json.NewEncoder(w).Encode(n)
				case "/v1/personal-notifications/7/prepare":
					prepares++
					if scenario == "upstream-error" || scenario == "pending-confirmation" {
						http.Error(w, "unavailable", http.StatusServiceUnavailable)
						return
					}
					token := "old"
					if prepares == 2 {
						token = "current"
					}
					_ = json.NewEncoder(w).
						Encode(map[string]any{"eligible": scenario != "optout" || prepares < 2, "notification": n, "token": token})
				case "/v1/personal-notifications/7/complete":
					var body struct {
						Sent     bool
						Terminal bool
						Delay    int `json:"delay_seconds"`
					}
					if e := json.NewDecoder(r.Body).Decode(&body); e != nil {
						t.Fatal(e)
					}
					completed = true
					switch scenario {
					case "success":
						if !body.Sent || body.Terminal {
							t.Error("success completion wrong")
						}
					case "blocked", "optout":
						if body.Sent || !body.Terminal {
							t.Error("terminal completion wrong")
						}
					case "rate-limit":
						if body.Sent || body.Terminal || body.Delay != 900 {
							t.Error("retry_after ignored", body.Delay)
						}
					case "upstream-error", "pending-confirmation":
						if body.Sent || body.Terminal || body.Delay == 0 {
							t.Error("transient failure not retryable")
						}
					}
					_, _ = w.Write([]byte(`{"ok":true}`))
				default:
					t.Error("sender attempted issuance/unexpected endpoint", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer relay.Close()
			api := &tgbotapi.BotAPI{Client: &http.Client{Transport: reliabilityRoundTrip(func(r *http.Request) (*http.Response, error) {
				sends++
				var body map[string]any
				if e := json.NewDecoder(r.Body).Decode(&body); e != nil {
					t.Fatal(e)
				}
				if body["chat_id"] != float64(123) || !strings.Contains(body["text"].(string), "https://example.com/sub/current") ||
					strings.Contains(body["text"].(string), "/sub/old") ||
					body["reply_markup"] == nil {
					t.Error("wrong recipient/current subscription/cabinet", body)
				}
				response := `{"ok":true,"result":{}}`
				if scenario == "rate-limit" {
					response = `{"ok":false,"error_code":429,"parameters":{"retry_after":900}}`
				}
				if scenario == "blocked" {
					response = `{"ok":false,"error_code":403}`
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(response)), Header: make(http.Header)}, nil
			})}}
			b := &Bot{
				api:         api,
				botToken:    "synthetic",
				adminAPIURL: relay.URL,
				miniAppURL:  "https://example.com/old/base?old=query#fragment",
			}
			if !b.sendPersonalNotification(context.Background()) || !completed {
				t.Fatal("delivery not completed")
			}
			want := 1
			if scenario == "optout" || scenario == "upstream-error" || scenario == "pending-confirmation" {
				want = 0
			}
			if sends != want {
				t.Fatalf("Telegram calls=%d want %d", sends, want)
			}
		})
	}
}
