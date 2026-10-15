package bot

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/NikitaDmitryuk/ultra/internal/db"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

func TestConstructionDoesNotContactTelegram(t *testing.T) {
	t.Setenv("ULTRA_BOT_TELEGRAM_SOCKS5", "127.0.0.1:1")
	started := time.Now()
	b, err := New("offline-token", "http://127.0.0.1:1", "admin", "https://example.test", nil, nil, nil)
	if err != nil || time.Since(started) > time.Second {
		t.Fatal("local initialization depends on network", err)
	}
	w := httptest.NewRecorder()
	b.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/happ", nil))
	if w.Code != 200 {
		t.Fatal("import page unavailable offline", w.Code)
	}
}
func TestFailedDeliveryIsNotAcknowledged(t *testing.T) {
	repo := &fakeAlertsTele{}
	sender := &fakeMsgSender{err: errors.New("send failed")}
	_ = repo.EnqueueNotification(context.Background(), db.Notification{TelegramID: 1})
	b := &Bot{alertsTele: repo, msgSender: sender}
	b.flushOutboxOnce(context.Background())
	if repo.rows[0].SentAt != nil {
		t.Fatal("failed delivery marked sent")
	}
	sender.err = nil
	b.flushOutboxOnce(context.Background())
	if repo.rows[0].SentAt == nil || sender.calls != 2 {
		t.Fatal("queued notification was lost")
	}
}
func TestRetryAfterAndTerminalDelivery(t *testing.T) {
	after, terminal := telegramFailure(tgbotapi.Error{Code: 429, ResponseParameters: tgbotapi.ResponseParameters{RetryAfter: 73}})
	if terminal || retryDelay(0, after) != 73*time.Second {
		t.Fatal("retry_after ignored")
	}
	_, terminal = telegramFailure(tgbotapi.Error{Code: 403})
	if !terminal {
		t.Fatal("permanent recipient failure not terminal")
	}
	_, terminal = telegramFailure(tgbotapi.Error{Code: 401})
	if terminal {
		t.Fatal("bot credential failure discarded queued message")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitTelegramRetry(ctx, time.Hour) {
		t.Fatal("shutdown did not interrupt retry")
	}
}
func TestSubscriptionCacheBootOutageExpirationAndRevocation(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	key := subscriptionCacheKey(token, "")
	path := filepath.Join(t.TempDir(), "subscriptions.json")
	b := &Bot{adminAPIURL: "http://127.0.0.1:1"}
	if err := b.ConfigureSubscriptionCache(path); err != nil {
		t.Fatal(err)
	}
	entry := cachedSubscription{
		Body:        []byte("vless://cached"),
		Headers:     map[string]string{"Content-Type": "text/plain"},
		ConfirmedAt: time.Now(),
	}
	if err := b.subscriptionCache.replace(map[string]cachedSubscription{key: entry}); err != nil {
		t.Fatal(err)
	}
	restarted := &Bot{adminAPIURL: b.adminAPIURL}
	if err := restarted.ConfigureSubscriptionCache(path); err != nil {
		t.Fatal(err)
	}
	request := func(bot *Bot) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/sub/"+token, nil)
		r.SetPathValue("token", token)
		r.TLS = &tls.ConnectionState{}
		w := httptest.NewRecorder()
		bot.handlePublicSubscription(w, r)
		return w
	}
	if w := request(restarted); w.Code != 200 || w.Body.String() != "vless://cached" {
		t.Fatal("cache failed after process restart", w.Code)
	}
	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) }))
	defer deny.Close()
	restarted.adminAPIURL = deny.URL
	if w := request(restarted); w.Code != 404 {
		t.Fatal("revoked subscription served stale", w.Code)
	}
	restarted.adminAPIURL = b.adminAPIURL
	if w := request(restarted); w.Code != 503 {
		t.Fatal("revoked token remained in cache", w.Code)
	}
	entry.ConfirmedAt = time.Now().Add(-25 * time.Hour)
	if err := restarted.subscriptionCache.replace(map[string]cachedSubscription{key: entry}); err != nil {
		t.Fatal(err)
	}
	if w := request(restarted); w.Code != 503 {
		t.Fatal("expired subscription served", w.Code)
	}
}
func TestCompleteCacheRefreshIncludesUndownloadedAndRemovesMissing(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	key := subscriptionCacheKey(token, "format=happ")
	entries := map[string]cachedSubscription{key: {Body: []byte("[]"), ConfirmedAt: time.Now()}}
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/subscriptions/cache" || r.Header.Get("Authorization") != "Bearer admin" {
			t.Error("invalid cache authentication")
		}
		_ = json.NewEncoder(w).Encode(subscriptionCacheSnapshot{Version: 1, Entries: entries})
	}))
	defer source.Close()
	b := &Bot{adminAPIURL: source.URL, adminAPIToken: "admin"}
	if err := b.ConfigureSubscriptionCache(filepath.Join(t.TempDir(), "cache.json")); err != nil {
		t.Fatal(err)
	}
	if err := b.refreshSubscriptionCache(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.subscriptionCache.get(key); !ok {
		t.Fatal("undownloaded profile not populated")
	}
	entries = map[string]cachedSubscription{}
	if err := b.refreshSubscriptionCache(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.subscriptionCache.get(key); ok {
		t.Fatal("complete refresh retained revoked token")
	}
}

func TestReadinessRequiresControlButNotTelegram(t *testing.T) {
	mode := "online"
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"runtime": map[string]string{"mode": mode}})
	}))
	defer relay.Close()
	b := &Bot{adminAPIURL: relay.URL}
	b.SetDatabaseProbe(func(context.Context) bool { return true })
	check := func(want int) {
		t.Helper()
		w := httptest.NewRecorder()
		b.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
		if w.Code != want {
			t.Fatal("wrong readiness", w.Code, w.Body.String())
		}
	}
	check(200)
	mode = "autonomous"
	check(503)
	b.SetDatabaseProbe(func(context.Context) bool { return false })
	check(503)
	w := httptest.NewRecorder()
	b.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
	if w.Code != 200 {
		t.Fatal("process liveness tied to database")
	}
}

func TestKnownRevocationWinsInflightBulkCacheRefresh(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	key := subscriptionCacheKey(token, "")
	other := subscriptionCacheKey(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), "")
	entries := map[string]cachedSubscription{
		key:   {Body: []byte("vless://old"), ConfirmedAt: time.Now()},
		other: {Body: []byte("vless://other"), ConfirmedAt: time.Now()},
	}
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/subscriptions/cache" {
			close(started)
			<-release
			_ = json.NewEncoder(w).Encode(subscriptionCacheSnapshot{Version: 1, Entries: entries})
			return
		}
		w.WriteHeader(404)
	}))
	defer func() { once.Do(func() { close(release) }); source.Close() }()
	path := filepath.Join(t.TempDir(), "cache.json")
	b := &Bot{adminAPIURL: source.URL, adminAPIToken: "admin"}
	if err := b.ConfigureSubscriptionCache(path); err != nil {
		t.Fatal(err)
	}
	if err := b.subscriptionCache.replace(entries); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- b.refreshSubscriptionCache(context.Background()) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("bulk refresh did not start")
	}
	request := httptest.NewRequest("GET", "/sub/"+token, nil)
	request.SetPathValue("token", token)
	request.TLS = &tls.ConnectionState{}
	response := httptest.NewRecorder()
	b.handlePublicSubscription(response, request)
	if response.Code != 404 {
		t.Fatalf("revocation ignored: %d", response.Code)
	}
	once.Do(func() { close(release) })
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("stale bulk response accepted after revocation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bulk refresh did not finish")
	}
	if _, ok := b.subscriptionCache.get(key); ok {
		t.Fatal("bulk resurrected revoked token")
	}
	if _, ok := b.subscriptionCache.get(other); !ok {
		t.Fatal("revocation removed unrelated token")
	}
	restarted := &Bot{}
	if err := restarted.ConfigureSubscriptionCache(path); err != nil {
		t.Fatal(err)
	}
	if _, ok := restarted.subscriptionCache.get(key); ok {
		t.Fatal("revocation was not persisted")
	}
	if _, ok := restarted.subscriptionCache.get(other); !ok {
		t.Fatal("unrelated token lost on restart")
	}
}

func TestTruncatedSubscriptionHTTP200UsesConfirmedCache(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	key := subscriptionCacheKey(token, "")
	confirmed := time.Now().Add(-time.Hour)
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "1024")
		_, _ = w.Write([]byte("partial"))
	}))
	defer source.Close()
	b := &Bot{adminAPIURL: source.URL}
	if err := b.ConfigureSubscriptionCache(filepath.Join(t.TempDir(), "cache.json")); err != nil {
		t.Fatal(err)
	}
	if err := b.subscriptionCache.replace(map[string]cachedSubscription{key: {Body: []byte("vless://confirmed\n"), Headers: map[string]string{"Content-Type": "text/plain"}, ConfirmedAt: confirmed}}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/sub/"+token, nil)
	req.SetPathValue("token", token)
	req.TLS = &tls.ConnectionState{}
	response := httptest.NewRecorder()
	b.handlePublicSubscription(response, req)
	if response.Code != 200 || response.Body.String() != "vless://confirmed\n" || response.Header().Get("X-Ultra-State") != "cached" ||
		response.Header().Get("Content-Type") != "text/plain" {
		t.Fatalf("truncated body escaped fallback: %d %q %v", response.Code, response.Body.String(), response.Header())
	}
	cached, ok := b.subscriptionCache.get(key)
	if !ok || !cached.ConfirmedAt.Equal(confirmed) {
		t.Fatal("network failure renewed cache lifetime")
	}
}

func TestInvalidBulkResponseRetainsOriginalCacheLease(t *testing.T) {
	for _, bad := range []string{"truncated", "invalid-json", "expired"} {
		t.Run(bad, func(t *testing.T) {
			key := "existing?format=happ"
			confirmed := time.Now().Add(-time.Hour)
			entries := map[string]cachedSubscription{key: {Body: []byte("confirmed"), ConfirmedAt: confirmed}}
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				switch bad {
				case "truncated":
					w.Header().Set("Content-Length", "1024")
					_, _ = w.Write([]byte(`{"version":1`))
				case "invalid-json":
					_, _ = w.Write([]byte("{"))
				case "expired":
					_ = json.NewEncoder(w).
						Encode(subscriptionCacheSnapshot{Version: 1, Entries: map[string]cachedSubscription{key: {Body: []byte("expired"), ConfirmedAt: time.Now().Add(-25 * time.Hour)}}})
				}
			}))
			defer source.Close()
			b := &Bot{adminAPIURL: source.URL}
			if err := b.ConfigureSubscriptionCache(filepath.Join(t.TempDir(), "cache.json")); err != nil {
				t.Fatal(err)
			}
			if err := b.subscriptionCache.replace(entries); err != nil {
				t.Fatal(err)
			}
			if err := b.refreshSubscriptionCache(context.Background()); err == nil {
				t.Fatal("bad bulk response accepted")
			}
			v, ok := b.subscriptionCache.get(key)
			if !ok || string(v.Body) != "confirmed" || !v.ConfirmedAt.Equal(confirmed) {
				t.Fatal("failed refresh replaced or renewed last confirmed cache")
			}
		})
	}
}

func TestTelegramFailurePreservesValueAndPointerErrors(t *testing.T) {
	for _, err := range []error{tgbotapi.Error{Code: 429, ResponseParameters: tgbotapi.ResponseParameters{RetryAfter: 73}}, &tgbotapi.Error{Code: 429, ResponseParameters: tgbotapi.ResponseParameters{RetryAfter: 73}}, fmt.Errorf("send: %w", error(&tgbotapi.Error{Code: 429, ResponseParameters: tgbotapi.ResponseParameters{RetryAfter: 73}}))} {
		after, terminal := telegramFailure(err)
		if after != 73 || terminal {
			t.Fatalf("rate limit lost for %T: %d %v", err, after, terminal)
		}
	}
	for _, code := range []int{400, 401, 403} {
		for _, err := range []error{tgbotapi.Error{Code: code}, &tgbotapi.Error{Code: code}} {
			_, terminal := telegramFailure(err)
			if terminal != (code != 401) {
				t.Fatalf("wrong terminal decision %d %T: %v", code, err, terminal)
			}
		}
	}
}

type reliabilityClaims struct {
	*fakeAlertsTele
	claims, completes, retries int
	attempt                    int
	next                       time.Time
	terminal                   bool
}

func (r *reliabilityClaims) ClaimNotifications(_ context.Context, limit int, lease time.Duration) ([]db.Notification, error) {
	r.claims++
	if limit != 1 || lease < time.Minute {
		return nil, errors.New("unsafe claim size or lease")
	}
	if r.claims > 1 {
		return nil, nil
	}
	return []db.Notification{{ID: 7, TelegramID: 123, Attempts: 3, Payload: map[string]any{"text": "queued"}}}, nil
}
func (r *reliabilityClaims) CompleteClaim(_ context.Context, id int64, attempt int) error {
	r.completes++
	r.attempt = attempt
	if id != 7 {
		return errors.New("wrong identity")
	}
	return nil
}
func (r *reliabilityClaims) RetryClaim(_ context.Context, id int64, attempt int, next time.Time, _ string, terminal bool) error {
	r.retries++
	r.attempt = attempt
	r.next = next
	r.terminal = terminal
	if id != 7 {
		return errors.New("wrong identity")
	}
	return nil
}

type reliabilityRoundTrip func(*http.Request) (*http.Response, error)

func (f reliabilityRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestProductionOutboxSendIsBoundedAndUsesRetryAfter(t *testing.T) {
	repo := &reliabilityClaims{fakeAlertsTele: &fakeAlertsTele{}}
	requests := 0
	client := &http.Client{Transport: reliabilityRoundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > 8*time.Second {
			t.Error("production delivery has no eight-second deadline")
		}
		if r.Method != "POST" || !strings.HasSuffix(r.URL.Path, "/sendMessage") {
			t.Error("unexpected Telegram method")
		}
		return &http.Response{
			StatusCode: 429,
			Body:       io.NopCloser(strings.NewReader(`{"ok":false,"error_code":429,"parameters":{"retry_after":73}}`)),
			Header:     make(http.Header),
		}, nil
	})}
	api := &tgbotapi.BotAPI{Token: "synthetic", Client: client}
	b := &Bot{api: api, botToken: "synthetic", msgSender: api, alertsTele: repo}
	started := time.Now()
	b.flushOutboxOnce(context.Background())
	if requests != 1 || repo.claims != 1 || repo.retries != 1 || repo.completes != 0 || repo.attempt != 3 || repo.terminal {
		t.Fatalf("rate limit lost claim: %#v sends=%d", repo, requests)
	}
	if repo.next.Before(started.Add(73*time.Second)) || repo.next.After(time.Now().Add(73*time.Second)) {
		t.Fatal("retry_after was not scheduled exactly")
	}
}
func TestClaimedOutboxPointerFailureDoesNotAcknowledge(t *testing.T) {
	repo := &reliabilityClaims{fakeAlertsTele: &fakeAlertsTele{}}
	sender := &fakeMsgSender{err: &tgbotapi.Error{Code: 403}}
	b := &Bot{alertsTele: repo, msgSender: sender}
	b.flushOutboxOnce(context.Background())
	if repo.retries != 1 || !repo.terminal || repo.completes != 0 || repo.attempt != 3 {
		t.Fatalf("permanent failure lost its claim: %#v", repo)
	}
}

func TestFirstBulkRefreshCannotPopulateTokenRevokedWhileInflight(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	key := subscriptionCacheKey(token, "")
	entries := map[string]cachedSubscription{key: {Body: []byte("revoked"), ConfirmedAt: time.Now()}}
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/subscriptions/cache" {
			close(started)
			<-release
			_ = json.NewEncoder(w).Encode(subscriptionCacheSnapshot{Version: 1, Entries: entries})
			return
		}
		w.WriteHeader(404)
	}))
	defer func() { once.Do(func() { close(release) }); source.Close() }()
	b := &Bot{adminAPIURL: source.URL}
	if err := b.ConfigureSubscriptionCache(filepath.Join(t.TempDir(), "cache.json")); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- b.refreshSubscriptionCache(context.Background()) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh did not start")
	}
	req := httptest.NewRequest("GET", "/sub/"+token, nil)
	req.SetPathValue("token", token)
	req.TLS = &tls.ConnectionState{}
	response := httptest.NewRecorder()
	b.handlePublicSubscription(response, req)
	if response.Code != 404 {
		t.Fatal("revocation response lost")
	}
	once.Do(func() { close(release) })
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("refresh did not finish")
	}
	if _, ok := b.subscriptionCache.get(key); ok {
		t.Fatal("first refresh resurrected an uncached revoked token")
	}
	// A later fresh response is independent; ephemeral invalidation metadata must be gone.
	b.subscriptionCache.mu.RLock()
	active := b.subscriptionCache.revokedDuringRefresh != nil
	b.subscriptionCache.mu.RUnlock()
	if active {
		t.Fatal("ephemeral revocations survived request completion")
	}
}
func TestInflightRevocationsAreBoundedAndOverflowRejectsBulk(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_ = json.NewEncoder(w).Encode(subscriptionCacheSnapshot{Version: 1, Entries: map[string]cachedSubscription{}})
	}))
	defer func() { once.Do(func() { close(release) }); source.Close() }()
	b := &Bot{adminAPIURL: source.URL}
	if err := b.ConfigureSubscriptionCache(filepath.Join(t.TempDir(), "cache.json")); err != nil {
		t.Fatal(err)
	}
	existing := map[string]cachedSubscription{"existing?": {Body: []byte("confirmed"), ConfirmedAt: time.Now()}}
	if err := b.subscriptionCache.replace(existing); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- b.refreshSubscriptionCache(context.Background()) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh did not start")
	}
	for i := range 1025 {
		b.subscriptionCache.invalidate(subscriptionDigest(fmt.Sprint(i)))
	}
	b.subscriptionCache.mu.RLock()
	count := len(b.subscriptionCache.revokedDuringRefresh)
	overflow := b.subscriptionCache.revocationOverflow
	b.subscriptionCache.mu.RUnlock()
	if count != 1024 || !overflow {
		t.Fatalf("unbounded revocations %d %v", count, overflow)
	}
	once.Do(func() { close(release) })
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("overflow replaced cache")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("refresh did not finish")
	}
	if _, ok := b.subscriptionCache.get("existing?"); !ok {
		t.Fatal("overflow destroyed last good cache")
	}
	b.subscriptionCache.invalidate(subscriptionDigest("unknown-outside-refresh"))
	b.subscriptionCache.mu.RLock()
	active := b.subscriptionCache.revokedDuringRefresh != nil
	b.subscriptionCache.mu.RUnlock()
	if active {
		t.Fatal("unknown token created persistent invalidation state")
	}
}

func TestFormerAdminMemberNotificationIsCanceledNotMarkedSent(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set: isolated PostgreSQL required")
	}
	ctx := context.Background()
	control, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := pgx.Identifier{"ultra_bot_test_" + uuid.NewString()}.Sanitize()
	if _, err = control.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		_ = control.Close(ctx)
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = control.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); _ = control.Close(ctx) })
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	database, err := db.Open(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	if _, err = database.Pool.Exec(ctx, `INSERT INTO users(uuid,name,telegram_id,enrollment_source) VALUES($1,'member',123456,'invite')`, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if _, err = database.Pool.Exec(ctx, `INSERT INTO vpn_member_notifications(member_id,admin_id) VALUES(123456,42)`); err != nil {
		t.Fatal(err)
	}
	sends := 0
	api := &tgbotapi.BotAPI{Client: &http.Client{Transport: reliabilityRoundTrip(func(*http.Request) (*http.Response, error) {
		sends++
		return nil, errors.New("unexpected send to former administrator")
	})}}
	b := &Bot{api: api, botToken: "synthetic", adminRepo: db.NewBotAdminRepo(database), teleRepo: db.NewTelegramRepo(database)}
	b.flushMemberNotificationsOnce(ctx)
	var sentAt *time.Time
	var terminal bool
	var reason string
	if err = database.Pool.QueryRow(ctx, `SELECT sent_at,terminal,last_error FROM vpn_member_notifications WHERE member_id=123456 AND admin_id=42`).Scan(&sentAt, &terminal, &reason); err != nil {
		t.Fatal(err)
	}
	if sends != 0 || sentAt != nil || !terminal || reason != "recipient_not_admin" {
		t.Fatalf("former administrator counted as delivered: sends=%d sent=%v terminal=%v reason=%q", sends, sentAt, terminal, reason)
	}
	pending, err := b.teleRepo.ClaimMemberNotifications(ctx)
	if err != nil || len(pending) != 0 {
		t.Fatal("canceled notification reclaimed")
	}
}

type reliabilityUnavailableAdmin struct{ fakeAdminLister }

func (*reliabilityUnavailableAdmin) IsAdmin(context.Context, int64) (bool, error) {
	return false, errors.New("database unavailable")
}
func TestAdminLookupOutageIsExplicitAndCannotMutateRelay(t *testing.T) {
	for _, scenario := range []string{"invite", "group_selection", "callback"} {
		t.Run(scenario, func(t *testing.T) {
			relayCalls := 0
			relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				relayCalls++
				t.Error("relay mutation attempted while admin DB unavailable")
				w.WriteHeader(500)
			}))
			defer relay.Close()
			messages := []map[string]any{}
			methods := []string{}
			api := &tgbotapi.BotAPI{Client: &http.Client{Transport: reliabilityRoundTrip(func(r *http.Request) (*http.Response, error) {
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				messages = append(messages, body)
				methods = append(methods, r.URL.Path)
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(`{"ok":true,"result":true}`)),
					Header:     make(http.Header),
				}, nil
			})}}
			b := &Bot{api: api, botToken: "synthetic", adminRepo: &reliabilityUnavailableAdmin{}, adminAPIURL: relay.URL}
			msg := &tgbotapi.Message{From: &tgbotapi.User{ID: 42}, Chat: &tgbotapi.Chat{ID: 42, Type: "private"}, Text: "/invitevpn 123"}
			switch scenario {
			case "invite":
				b.inviteVPNCommand(context.Background(), msg)
			case "group_selection":
				b.handleGroupShared(context.Background(), msg, sharedGroup{RequestID: 1, ChatID: -100})
			case "callback":
				b.handleMemberCallback(
					context.Background(),
					&tgbotapi.CallbackQuery{ID: "callback", From: msg.From, Message: msg, Data: "vpn_disable:123"},
				)
			}
			if relayCalls != 0 || len(messages) != 1 {
				t.Fatalf("missing explicit failure or attempted mutation: calls=%d messages=%v", relayCalls, messages)
			}
			text, _ := messages[0]["text"].(string)
			if !strings.Contains(text, "Сервис временно недоступен") || strings.Contains(text, "Только администратор") ||
				strings.Contains(text, "сохранено") {
				t.Fatalf("DB error misreported as permissions/success: %q", text)
			}
			if scenario == "callback" {
				if !strings.HasSuffix(methods[0], "/answerCallbackQuery") || messages[0]["show_alert"] != true ||
					messages[0]["callback_query_id"] != "callback" {
					t.Fatal("callback spinner was not closed with error alert")
				}
			} else if !strings.HasSuffix(methods[0], "/sendMessage") {
				t.Fatal("command error was not sent")
			}
		})
	}
}

func TestSubscriptionCacheSeparatesEffectiveFormats(t *testing.T) {
	token := "synthetic"
	b := &Bot{subscriptionCache: &subscriptionCache{happDefaultJSON: true, entries: map[string]cachedSubscription{
		subscriptionCacheKey(token, "format=happ"):                    {Body: []byte("json"), ConfirmedAt: time.Now()},
		subscriptionCacheKey(token, "format=uri"):                     {Body: []byte("uri"), ConfirmedAt: time.Now()},
		subscriptionCacheKey(token, "format=uri&transport=xhttp-tls"): {Body: []byte("tls-uri"), ConfirmedAt: time.Now()},
	}}}
	for _, c := range []struct{ query, ua, want string }{
		{"", "Happ/4.7.1/Android/fixture-device", "json"}, {"", "Other", "uri"}, {"format=uri", "Happ/4.7.1/Android/fixture-device", "uri"}, {"format=happ", "Other", "json"},
		{"transport=xhttp-tls", "Happ/4.7.1/Android/fixture-device", "tls-uri"},
		{"format=uri&transport=xhttp-tls", "Happ/4.7.1/Android/fixture-device", "tls-uri"},
	} {
		r := httptest.NewRequest("GET", "/sub/test?"+c.query, nil)
		r.Header.Set("User-Agent", c.ua)
		key, err := b.subscriptionFallbackKey(token, r)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		if !b.serveSubscriptionFallback(w, key, token, r) || w.Body.String() != c.want || w.Header().Get("Vary") != "User-Agent" ||
			w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal(c, w.Body.String())
		}
	}
	r := httptest.NewRequest("GET", "/sub/test?format=happ&preview=reserve", nil)
	if b.serveSubscriptionFallback(httptest.NewRecorder(), subscriptionCacheKey(token, "format=happ"), token, r) {
		t.Fatal("preview cached")
	}
	// Simulate refresh between the initial key calculation and outage fallback.
	oldKey := subscriptionCacheKey(token, "format=happ")
	b.subscriptionCache.happDefaultJSON = false
	r = httptest.NewRequest("GET", "/sub/test", nil)
	r.Header.Set("User-Agent", "Happ/3")
	w := httptest.NewRecorder()
	if !b.serveSubscriptionFallback(w, oldKey, token, r) || w.Body.String() != "uri" {
		t.Fatal("mixed cache generations on rollback", w.Body.String())
	}
	r = httptest.NewRequest("GET", "/sub/test", nil)
	r.Header.Set("User-Agent", "Happ/3")
	key, _ := b.subscriptionFallbackKey(token, r)
	if key != subscriptionCacheKey(token, "format=uri") {
		t.Fatal("rollback does not select URI")
	}
}

func TestSubscriptionPolicyRefreshAndRestart(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	snapshot := subscriptionCacheSnapshot{Version: 1, HappDefaultJSON: true, Entries: map[string]cachedSubscription{
		subscriptionCacheKey(token, "format=uri"): {
			Body:        []byte("uri"),
			Headers:     map[string]string{"Content-Type": "text/plain", "Vary": "User-Agent"},
			ConfirmedAt: time.Now(),
		},
		subscriptionCacheKey(token, "format=happ"): {
			Body:        []byte("[]"),
			Headers:     map[string]string{"Content-Type": "application/json", "Vary": "User-Agent"},
			ConfirmedAt: time.Now(),
		},
	}}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/subscriptions/cache" {
			_ = json.NewEncoder(w).Encode(snapshot)
			return
		}
		w.WriteHeader(503)
	}))
	defer upstream.Close()
	path := filepath.Join(t.TempDir(), "cache.json")
	b := &Bot{adminAPIURL: upstream.URL}
	if err := b.ConfigureSubscriptionCache(path); err != nil {
		t.Fatal(err)
	}
	if err := b.refreshSubscriptionCache(context.Background()); err != nil {
		t.Fatal(err)
	}
	check := func(want string) {
		restarted := &Bot{adminAPIURL: upstream.URL}
		if err := restarted.ConfigureSubscriptionCache(path); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", "/sub/"+token, nil)
		r.SetPathValue("token", token)
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("User-Agent", "Happ/3 Android")
		w := httptest.NewRecorder()
		restarted.handlePublicSubscription(w, r)
		if w.Code != 200 || w.Body.String() != want || w.Header().Get("Vary") != "User-Agent" {
			t.Fatal("policy/representation lost", w.Code, w.Body.String())
		}
		if strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") != (want == "[]") {
			t.Fatal("wrong content type")
		}
	}
	check("[]")
	snapshot.HappDefaultJSON = false
	if err := b.refreshSubscriptionCache(context.Background()); err != nil {
		t.Fatal(err)
	}
	check("uri")
	// A failed refresh cannot publish a policy different from the retained generation.
	snapshot.HappDefaultJSON = true
	for key, entry := range snapshot.Entries {
		entry.ConfirmedAt = time.Now().Add(-25 * time.Hour)
		snapshot.Entries[key] = entry
	}
	if err := b.refreshSubscriptionCache(context.Background()); err == nil {
		t.Fatal("stale policy accepted")
	}
	check("uri")
}
