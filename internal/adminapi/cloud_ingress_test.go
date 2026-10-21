package adminapi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
)

func TestIngressErrorContract(t *testing.T) {
	w := httptest.NewRecorder()
	cloudResult(w, nil, cloud.ErrIngressInUse)
	var v map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if w.Code != 409 || v["code"] != "ingress_in_use" || v["message"] == "" {
		t.Fatalf("unexpected response: %d %v", w.Code, v)
	}
}

func TestDeletedCloudExitsAreFilteredByIdentity(t *testing.T) {
	deleted := deletedCloudExitIDs([]cloud.Operation{
		{ExitID: "atlanta-old", State: "deleted"},
		{ExitID: "atlanta-current", State: "ready"},
		{ExitID: "frankfurt-pending", State: "pending"},
	})
	if !deleted["atlanta-old"] || deleted["atlanta-current"] || deleted["frankfurt-pending"] {
		t.Fatalf("unexpected deleted exit set: %v", deleted)
	}
}

func TestReplicaEndpointReturnsConfiguredStatus(t *testing.T) {
	s, err := NewServer("127.0.0.1:0", "secret", &fakeUserManager{}, nil, nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.ReplicationStatus = func(context.Context) (any, error) {
		return []map[string]any{{"id": "bridge-replica", "name": "Bridge", "state": "streaming"}}, nil
	}
	request := httptest.NewRequest("GET", "/v1/cloud/replicas", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	s.authMiddleware(s.mux).ServeHTTP(response, request)
	var values []map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &values); err != nil {
		t.Fatal(err)
	}
	if response.Code != 200 || len(values) != 1 || values[0]["state"] != "streaming" {
		t.Fatalf("unexpected replica response: %d %s", response.Code, response.Body.String())
	}
}
