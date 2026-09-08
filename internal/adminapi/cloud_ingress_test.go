package adminapi

import (
	"encoding/json"
	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"net/http/httptest"
	"testing"
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
