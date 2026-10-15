package bot

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAcceptanceUserAgentCaptureIsBoundedAndContainsOnlyAgent(t *testing.T) {
	var buf bytes.Buffer
	b := &Bot{log: slog.New(slog.NewJSONHandler(&buf, nil))}
	for range 20 {
		b.captureHappAcceptanceUserAgent(strings.Repeat("a", 512))
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 8 {
		t.Fatalf("unbounded acceptance diagnostics: %d", len(lines))
	}
	for _, line := range lines {
		var record map[string]any
		if json.Unmarshal([]byte(line), &record) != nil || len(record) != 4 || len(record["user_agent"].(string)) != 256 {
			t.Fatal("unexpected sensitive metadata or unbounded User-Agent")
		}
	}
}

const acceptanceBody = `[{"remarks":"Auto","outbounds":[{"protocol":"blackhole","tag":"block"},{"protocol":"vless","settings":{"vnext":[{"address":"bridge.test","port":443,"users":[{"id":"fixture"}]}]},"streamSettings":{"network":"xhttp","security":"tls"}},{"protocol":"vless","settings":{"vnext":[{"address":"bridge.test","port":24443,"users":[{"id":"fixture"}]}]},"streamSettings":{"network":"tcp","security":"reality"}}]}]`

func TestAcceptanceUsesAuthorisedPreviewAndNeverOfflineCache(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	digest := sha256.Sum256([]byte(token))
	c := happAcceptance{
		TokenDigest: hex.EncodeToString(digest[:]),
		IssuedAt:    time.Now().Add(-time.Minute),
		ExpiresAt:   time.Now().Add(time.Minute),
		PrimaryPort: 25443,
		ReservePort: 25444,
	}
	path := filepath.Join(t.TempDir(), "acceptance.json")
	data, _ := json.Marshal(c)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	upstreamStatus := 200
	expireDuringRequest := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if expireDuringRequest {
			c.ExpiresAt = time.Now().Add(-time.Second)
			body, _ := json.Marshal(c)
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Error(err)
			}
		}
		if r.URL.Query().Get("preview") != "reserve" || r.URL.Query().Get("format") != "happ" || r.UserAgent() != "Happ/fixture" {
			t.Error("authorised preview contract lost")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(upstreamStatus)
		_, _ = w.Write([]byte(acceptanceBody))
	}))
	defer upstream.Close()
	b := &Bot{adminAPIURL: upstream.URL, adminAPIToken: "fixture", happAcceptanceFile: path, log: slog.Default()}
	request := func(query, credential string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "https://example.test/sub/"+credential+"?"+query, nil)
		r.SetPathValue("token", credential)
		r.Header.Set("User-Agent", "Happ/fixture")
		w := httptest.NewRecorder()
		b.handlePublicSubscription(w, r)
		return w
	}
	w := request("format=happ&preview=reserve-live", token)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"port":25443`) || !strings.Contains(w.Body.String(), `"port":25444`) ||
		!strings.Contains(w.Body.String(), `"id":"fixture"`) ||
		w.Header().Get("Cache-Control") != "no-store" ||
		w.Header().Get("Vary") != "User-Agent" {
		t.Fatal(w.Code, w.Body.String())
	}
	upstreamStatus = 404
	if w = request("format=happ&preview=reserve-live", token); w.Code != 404 {
		t.Fatal("owner denial bypassed", w.Code)
	}
	upstreamStatus = 503
	if w = request("format=happ&preview=reserve-live", token); w.Code != 503 {
		t.Fatal("outage bypassed", w.Code)
	}
	prior := calls
	other := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	if request("format=happ&preview=reserve-live", other).Code != 404 || calls != prior {
		t.Fatal("acceptance available to another owner")
	}
	if request("format=uri&preview=reserve-live", token).Code != 400 || calls != prior {
		t.Fatal("explicit format overridden")
	}
	upstreamStatus = 200
	expireDuringRequest = true
	if request("format=happ&preview=reserve-live", token).Code != 503 {
		t.Fatal("acceptance revoked during upstream request was issued")
	}
	prior = calls
	b.happAcceptanceFile = ""
	if request("format=happ&preview=reserve-live", token).Code != 404 || calls != prior {
		t.Fatal("acceptance enabled by default")
	}
}

func TestAcceptanceExpiryPermissionsAndUnsafeProfile(t *testing.T) {
	token := "fixture"
	digest := sha256.Sum256([]byte(token))
	now := time.Now()
	c := happAcceptance{
		TokenDigest: hex.EncodeToString(digest[:]),
		IssuedAt:    now.Add(-time.Minute),
		ExpiresAt:   now.Add(time.Minute),
		PrimaryPort: 25443,
		ReservePort: 25444,
	}
	path := filepath.Join(t.TempDir(), "config.json")
	write := func() {
		t.Helper()
		body, _ := json.Marshal(c)
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	if _, err := loadHappAcceptance(path, token, now); err != nil {
		t.Fatal(err)
	}
	if _, err := loadHappAcceptance(path, token, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired acceptance allowed")
	}
	c.ExpiresAt = now.Add(2 * time.Hour)
	write()
	if _, err := loadHappAcceptance(path, token, now); err == nil {
		t.Fatal("unbounded acceptance allowed")
	}
	c.ExpiresAt = now.Add(time.Minute)
	write()
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadHappAcceptance(path, token, now); err == nil {
		t.Fatal("public config allowed")
	}
	if _, err := c.rewrite([]byte(strings.Replace(acceptanceBody, `"blackhole"`, `"freedom"`, 1))); err == nil {
		t.Fatal("direct exit allowed")
	}
	if _, err := c.rewrite([]byte(`[{"outbounds":[]}]`)); err == nil {
		t.Fatal("missing transport accepted")
	}
}
