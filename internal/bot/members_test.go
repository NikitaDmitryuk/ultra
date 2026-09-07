package bot

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/db"
)

func TestGroupMemberAdmission(t *testing.T) {
	for _, tc := range []struct {
		status       string
		member, want bool
	}{{"creator", false, true}, {"administrator", false, true}, {"member", false, true}, {"restricted", true, true}, {"restricted", false, false}, {"left", false, false}, {"kicked", false, false}, {"pending", true, false}, {"", true, false}} {
		if allowedMember(tc.status, tc.member) != tc.want {
			t.Errorf("wrong admission for %s / %v", tc.status, tc.member)
		}
	}
}

type nonAdmin struct{ fakeAdminLister }

func (*nonAdmin) IsAdmin(context.Context, int64) (bool, error) { return false, nil }
func TestSelfOwnerAndAdminIsolation(t *testing.T) {
	requests := []string{}
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path)
		switch r.URL.Path {
		case "/v1/members/123":
			_ = json.NewEncoder(w).Encode(db.Member{UUID: "owner", TelegramID: 123, Active: true})
		case "/v1/client/users/owner/exits":
			_, _ = w.Write([]byte(`{"exits":[]}`))
		default:
			t.Error("unexpected owner route", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer relay.Close()
	b := &Bot{botToken: "test-token", adminRepo: &nonAdmin{}, adminAPIURL: relay.URL}
	mux := http.NewServeMux()
	b.registerMiniAppRoutes(mux)
	for _, path := range []string{"/api/self/exits?uuid=other", "/api/members", "/api/cloud/operations"} {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set(initDataHeader, signedInitData(t, b.botToken, 123))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		want := http.StatusForbidden
		if strings.HasPrefix(path, "/api/self/") {
			want = http.StatusOK
		}
		if w.Code != want {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	if len(requests) != 2 {
		t.Fatal("admin route reached relay")
	}
	for _, signature := range []string{"forged", signedInitData(t, b.botToken, 123) + "&user=other"} {
		req := httptest.NewRequest("GET", "/api/self", nil)
		req.Header.Set(initDataHeader, signature)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatal("invalid session accepted")
		}
	}
}
