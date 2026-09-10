package adminapi

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/rtc"
)

type rtcSubscriptions struct {
	testSubscriptions
	owner string
}

func (s *rtcSubscriptions) Resolve(_ context.Context, token string) (string, error) {
	if token != "issued" {
		return "", errors.New("invalid")
	}
	return s.owner, nil
}
func TestRTCSubscriptionAuthorization(t *testing.T) {
	owner := "2784871e-d8a9-4e1f-b831-3d86aa8653ee"
	key := filepath.Join(t.TempDir(), "key")
	if e := os.WriteFile(key, []byte(strings.Repeat("a", 64)), 0600); e != nil {
		t.Fatal(e)
	}
	bindings := []rtc.Binding{{ID: "phone", UserUUID: owner, Enabled: true, Provider: "wbstream", RoomID: "room123", Transport: "vp8channel", ListenPort: 12001, KeyFile: key, PasswordFile: key + ".password", BootstrapDNS: "77.88.8.8:53"}}
	users := newFakeUserManager()
	users.users[owner] = auth.User{UUID: owner, IsActive: true}
	spec := &config.Spec{Role: config.RoleBridge, RTC: bindings}
	s, e := NewServer("127.0.0.1:0", "secret", users, nil, spec, nil, nil, nil, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	store := &rtcSubscriptions{owner: owner}
	s.Subscriptions = store
	request := func(token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/v1/subscriptions/"+token+"?format=olcrtc", nil)
		r.Header.Set("Authorization", "Bearer secret")
		w := httptest.NewRecorder()
		s.authMiddleware(s.mux).ServeHTTP(w, r)
		return w
	}
	w := request("issued")
	if w.Code != 404 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("disabled module exposed profile")
	}
	if w = request("bad"); w.Code != 404 {
		t.Fatal("invalid token accepted")
	}
}
