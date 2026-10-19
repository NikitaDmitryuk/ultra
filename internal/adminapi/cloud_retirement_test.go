package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
)

type retirementHistory struct {
	operations []cloud.Operation
	err        error
}

func (h retirementHistory) List(context.Context) ([]cloud.Operation, error) {
	return h.operations, h.err
}

func TestCloudRetirementExitListHidesOnlyDeletedTombstones(t *testing.T) {
	manager, err := exits.NewManager(selectionExitRepo{nodes: []exits.Node{
		{ID: "main", Enabled: true}, {ID: "deleted", Enabled: false}, {ID: "failed", Enabled: false},
	}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{exits: manager, CloudOperationHistory: retirementHistory{operations: []cloud.Operation{
		{ID: "op", ExitID: "deleted", State: "deleted"}, {ID: "other", ExitID: "failed", State: "failed"},
	}}}
	w := httptest.NewRecorder()
	s.handleListExits(w, httptest.NewRequest("GET", "/v1/exits", nil))
	var result struct {
		Exits  []exits.Node `json:"exits"`
		Active string       `json:"active_exit_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Exits) != 2 || result.Exits[0].ID != "main" || result.Exits[1].ID != "failed" || result.Active != "main" {
		t.Fatalf("unexpected list: %s", w.Body)
	}
	s.CloudOperationHistory = retirementHistory{err: errors.New("private-error")}
	w = httptest.NewRecorder()
	s.handleListExits(w, httptest.NewRequest("GET", "/v1/exits", nil))
	if w.Code != 503 || strings.Contains(w.Body.String(), "private-error") {
		t.Fatalf("history failure: %d %s", w.Code, w.Body)
	}
}

func TestCloudRetirementRequiresAuthenticationAndExactPlan(t *testing.T) {
	s, err := NewServer("127.0.0.1:0", "secret", &fakeUserManager{}, nil, nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.Cloud = &cloud.Service{}
	for _, tc := range []struct {
		name, token, body string
		status            int
	}{
		{"unauthorized", "", `{"actor":1,"targets":[]}`, 401},
		{"empty-plan", "secret", `{"actor":1,"targets":[]}`, 409},
		{"invalid-json", "secret", `{`, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/v1/cloud/retirement", strings.NewReader(tc.body))
			if tc.token != "" {
				r.Header.Set("Authorization", "Bearer "+tc.token)
			}
			w := httptest.NewRecorder()
			s.authMiddleware(s.mux).ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status=%d body=%s", w.Code, w.Body)
			}
		})
	}
}
