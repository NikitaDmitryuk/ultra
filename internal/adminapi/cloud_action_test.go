package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
)

type actionGateStore struct{ cloud.Store }

func (actionGateStore) Lock(context.Context) (func(), error) { return func() {}, nil }

type readinessFailure string

func (e readinessFailure) Error() string         { return "private-controller-token" }
func (e readinessFailure) ReadinessCode() string { return string(e) }

func TestCloudActionReportsOnlySafeReadinessDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code string
	}{
		{"busy", readinessFailure("lifecycle_busy"), "lifecycle_busy"},
		{"unavailable", readinessFailure("controller_unavailable"), "controller_unavailable"},
		{"untrusted_code", readinessFailure("private-controller-token"), "operation_unavailable"},
		{"unknown", errors.New("private-controller-token"), "operation_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewServer("127.0.0.1:0", "secret", &fakeUserManager{}, nil, nil, nil, nil, nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			s.log = slog.New(slog.NewJSONHandler(&logs, nil))
			s.Cloud = &cloud.Service{Store: actionGateStore{}, TopologyReady: func(context.Context) error { return tc.err }}
			r := httptest.NewRequest("POST", "/v1/cloud/operations/private-operation/action", strings.NewReader(`{"action":"delete","actor":1}`))
			r.Header.Set("Authorization", "Bearer secret")
			w := httptest.NewRecorder()
			s.authMiddleware(s.mux).ServeHTTP(w, r)
			var response map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if w.Code != 503 || response["code"] != tc.code || response["message"] != cloud.ErrorMessage(tc.code) {
				t.Fatalf("response = %d %s", w.Code, w.Body)
			}
			if !strings.Contains(logs.String(), `"phase":"action"`) || !strings.Contains(logs.String(), `"error_code":"`+tc.code+`"`) {
				t.Fatalf("missing safe request log: %s", &logs)
			}
			for _, private := range []string{"private-controller-token", "private-operation", "Bearer", "secret"} {
				if strings.Contains(logs.String()+w.Body.String(), private) {
					t.Fatalf("request diagnostics exposed %q", private)
				}
			}
		})
	}
}
