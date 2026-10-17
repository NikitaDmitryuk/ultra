package vdsina

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testClient(server *httptest.Server, token string) *Client {
	c := New(token)
	c.baseURL = server.URL
	c.http = server.Client()
	c.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

func TestServersSendsRawTokenAndDecodesEnvelope(t *testing.T) {
	const token = "secret-token-value"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/server" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != token {
			t.Errorf("Authorization = %q", got)
		}
		_, _ = fmt.Fprint(w, `{"status":"ok","status_msg":"","data":[{"id":17,"name":"db","cpu":4}]}`)
	}))
	defer server.Close()
	got, err := testClient(server, token).Servers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got[0].ID) != "17" || got[0].Name != "db" || !strings.Contains(string(got[0].Raw), `"cpu":4`) {
		t.Fatalf("decoded servers = %#v", got)
	}
}

func TestErrorsDoNotExposeTokenOrResponseBody(t *testing.T) {
	const token = "secret-token-value"
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"http", http.StatusBadGateway, token},
		{"api", http.StatusOK, `{"status":"error","status_msg":"` + token + `","data":null}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			_, err := testClient(server, token).Servers(context.Background())
			if err == nil {
				t.Fatal("expected error")
			}
			if strings.Contains(err.Error(), token) {
				t.Fatalf("error leaked token: %v", err)
			}
		})
	}
}

func TestCreateServerMakesOnePostOnAmbiguousResponse(t *testing.T) {
	const token = "secret-token-value"
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/server" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != token {
			t.Errorf("Authorization = %q", got)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"status":"ok","data":{}}`)
	}))
	defer server.Close()
	_, err := testClient(server, token).CreateServer(context.Background(), CreateServerRequest{
		DatacenterID: 1, ServerPlanID: 2, TemplateID: 3, SSHKeyID: 4, Name: "db-host",
	})
	if err == nil {
		t.Fatal("expected missing ID error")
	}
	if posts != 1 {
		t.Fatalf("POST count = %d, want 1", posts)
	}
}

func TestCreateServerValidatesRequiredFieldsBeforeRequest(t *testing.T) {
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { posts++ }))
	defer server.Close()
	_, err := testClient(server, "token").CreateServer(context.Background(), CreateServerRequest{})
	if err == nil {
		t.Fatal("expected validation error")
	}
	if posts != 0 {
		t.Fatalf("POST count = %d, want 0", posts)
	}
}
