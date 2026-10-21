package bot

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDatabaseProxyAdminIsolation(t *testing.T) {
	calls := 0
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/v1/database" || r.Header.Get("Authorization") != "Bearer relay-secret" {
			t.Errorf("incorrect relay request: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"configured_host":"127.0.0.1","configured_port":25432,"observed_role":"primary","reachable":true}`))
	}))
	defer relay.Close()
	for _, admin := range []bool{false, true} {
		b := &Bot{botToken: "test-token", adminRepo: &fakeAdminLister{}, adminAPIURL: relay.URL, adminAPIToken: "relay-secret"}
		if !admin {
			b.adminRepo = &nonAdmin{}
		}
		mux := http.NewServeMux()
		b.registerMiniAppRoutes(mux)
		r := httptest.NewRequest("GET", "/api/database", nil)
		r.Header.Set(initDataHeader, signedInitData(t, b.botToken, 123))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		want := http.StatusForbidden
		if admin {
			want = http.StatusOK
		}
		if w.Code != want {
			t.Fatalf("admin=%v: status=%d body=%s", admin, w.Code, w.Body)
		}
	}
	if calls != 1 {
		t.Fatalf("unauthorized request reached relay: calls=%d", calls)
	}
}
