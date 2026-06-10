package bot

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/google/uuid"
)

func TestParseWindow(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    time.Duration
		wantErr bool
	}{
		{name: "default", in: "", want: 24 * time.Hour},
		{name: "1h", in: "1h", want: time.Hour},
		{name: "24h", in: "24h", want: 24 * time.Hour},
		{name: "7d", in: "7d", want: 7 * 24 * time.Hour},
		{name: "30d", in: "30d", want: 30 * 24 * time.Hour},
		{name: "invalid", in: "2d", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseWindow(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("duration mismatch: got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDefaultBucketForWindow(t *testing.T) {
	tests := []struct {
		window time.Duration
		want   string
	}{
		{window: time.Hour, want: "5m"},
		{window: 24 * time.Hour, want: "5m"},
		{window: 48 * time.Hour, want: "1h"},
		{window: 7 * 24 * time.Hour, want: "1h"},
		{window: 10 * 24 * time.Hour, want: "6h"},
		{window: 30 * 24 * time.Hour, want: "6h"},
		{window: 90 * 24 * time.Hour, want: "1d"},
	}
	for _, tc := range tests {
		got := defaultBucketForWindow(tc.window)
		if got != tc.want {
			t.Fatalf("bucket mismatch for %v: got %q, want %q", tc.window, got, tc.want)
		}
	}
}

func TestDefaultTrafficBucketForWindow(t *testing.T) {
	tests := []struct {
		window time.Duration
		want   string
	}{
		{window: time.Hour, want: "5m"},
		{window: 24 * time.Hour, want: "1h"},
		{window: 48 * time.Hour, want: "6h"},
		{window: 7 * 24 * time.Hour, want: "6h"},
		{window: 10 * 24 * time.Hour, want: "1d"},
		{window: 30 * 24 * time.Hour, want: "1d"},
		{window: 90 * 24 * time.Hour, want: "1d"},
	}
	for _, tc := range tests {
		got := defaultTrafficBucketForWindow(tc.window)
		if got != tc.want {
			t.Fatalf("traffic bucket mismatch for %v: got %q, want %q", tc.window, got, tc.want)
		}
	}
}

func TestHandleUserTrafficTimeline(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	database, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(database.Close)

	userUUID := uuid.NewString()
	t.Cleanup(func() {
		_, _ = database.Pool.Exec(context.Background(), `DELETE FROM users WHERE uuid=$1`, userUUID)
	})
	if _, err := database.Pool.Exec(ctx, `INSERT INTO users(uuid, name) VALUES($1, 'timeline-api-test')`, userUUID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	now := time.Now().UTC()
	hourStart := now.Truncate(time.Hour)
	if err := db.NewTrafficRepo(database).RecordSamples(ctx, []db.TrafficSample{
		{UserUUID: userUUID, CollectedAt: hourStart.Add(5 * time.Minute), UplinkBytes: 10, DownlinkBytes: 20},
		{UserUUID: userUUID, CollectedAt: hourStart.Add(35 * time.Minute), UplinkBytes: 30, DownlinkBytes: 40},
	}); err != nil {
		t.Fatalf("record samples: %v", err)
	}

	const token = "test-token"
	b := &Bot{
		botToken:  token,
		adminRepo: &fakeAdminLister{},
		teleRepo:  db.NewTelegramRepo(database),
	}
	req := httptest.NewRequest(http.MethodGet, "/api/users/"+userUUID+"/traffic/timeline?window=24h", nil)
	req.Header.Set(initDataHeader, signedInitData(t, token, 123))
	rr := httptest.NewRecorder()
	b.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Window string                    `json:"window"`
		Bucket string                    `json:"bucket"`
		Points []db.TrafficTimelinePoint `json:"points"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Window != "24h" || resp.Bucket != "1h" {
		t.Fatalf("unexpected window/bucket: %+v", resp)
	}
	if len(resp.Points) != 1 {
		t.Fatalf("point count=%d, want 1: %+v", len(resp.Points), resp.Points)
	}
	if resp.Points[0].UplinkBytes != 40 || resp.Points[0].DownlinkBytes != 60 || resp.Points[0].TotalBytes != 100 {
		t.Fatalf("unexpected point totals: %+v", resp.Points[0])
	}
}

func signedInitData(t *testing.T, botToken string, telegramID int64) string {
	t.Helper()
	userJSON := `{"id":` + strconv.FormatInt(telegramID, 10) + `,"first_name":"Test"}`
	authDate := strconv.FormatInt(time.Now().Unix(), 10)
	dataCheck := "auth_date=" + authDate + "\nuser=" + userJSON

	secretMAC := hmac.New(sha256.New, []byte("WebAppData"))
	secretMAC.Write([]byte(botToken))
	secret := secretMAC.Sum(nil)
	hashMAC := hmac.New(sha256.New, secret)
	hashMAC.Write([]byte(dataCheck))
	hash := hex.EncodeToString(hashMAC.Sum(nil))

	vals := url.Values{}
	vals.Set("auth_date", authDate)
	vals.Set("user", userJSON)
	vals.Set("hash", hash)
	return vals.Encode()
}
