package adminapi

import (
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
