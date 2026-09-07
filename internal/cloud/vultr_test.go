package cloud

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPaginationAndCreateDoesNotRetry(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Error("missing authorization")
		}
		if r.Method == "POST" {
			calls++
			http.Error(w, "upstream failure", 500)
			return
		}
		if r.URL.Query().Get("cursor") == "next" {
			_, _ = fmt.Fprint(w, `{"instances":[{"id":"b","default_password":"must-not-be-retained"}],"meta":{"links":{"next":""}}}`)
		} else {
			_, _ = fmt.Fprint(w, `{"instances":[{"id":"a"}],"meta":{"links":{"next":"next"}}}`)
		}
	}))
	defer server.Close()
	v := NewVultr("test-key")
	v.BaseURL = server.URL
	list, e := v.Instances(context.Background())
	if e != nil || len(list) != 2 {
		t.Fatal("pagination failed", e)
	}
	if _, e = v.Create(context.Background(), CreateRequest{}); !errors.Is(e, ErrUnknownCreation) || calls != 1 {
		t.Fatal("unsafe create retry", calls, e)
	}
}
func TestRedirectDoesNotForwardCredentials(t *testing.T) {
	destinationCalls := 0
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { destinationCalls++ }))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, http.StatusFound) }))
	defer source.Close()
	v := NewVultr("test-key")
	v.BaseURL = source.URL
	if _, e := v.Instances(context.Background()); e == nil || destinationCalls != 0 {
		t.Fatal("followed redirect")
	}
}
