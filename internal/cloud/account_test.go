package cloud

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccountFiltersIdentityAndRejectsMissingFigures(t *testing.T) {
	for _, body := range []string{`{"account":{"balance":12.5,"pending_charges":1.25,"email":"private@example.test","acl":["billing"]}}`, `{"account":{}}`, `{"account":{"balance":"NaN","pending_charges":0}}`} {
		t.Run(body, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer srv.Close()
			api := NewVultr("test")
			api.BaseURL = srv.URL
			a, e := api.Account(context.Background())
			if !strings.Contains(body, "12.5") {
				if e == nil {
					t.Fatal("invalid figures accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			data, e := json.Marshal(a)
			if e != nil {
				t.Fatal(e)
			}
			if strings.Contains(string(data), "private") || strings.Contains(string(data), "acl") || a.Balance.String() != "12.5" || a.ObservedAt.IsZero() {
				t.Fatal("bad billing DTO")
			}
		})
	}
}
