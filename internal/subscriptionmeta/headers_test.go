package subscriptionmeta

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAnnouncementStaysWithinHappLimitIncludingStalePrefix(t *testing.T) {
	h := http.Header{}
	Announce(h, strings.Repeat("к", 300))
	MarkStale(h, time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC))
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h.Get("announce"), "base64:"))
	if err != nil || len([]rune(string(raw))) > 200 || !strings.Contains(string(raw), "устарели") {
		t.Fatal(string(raw), err)
	}
}
