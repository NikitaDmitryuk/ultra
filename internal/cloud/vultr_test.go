package cloud

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestEnsureSSHKeyReusesKeyWithDifferentComment(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	material := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
			http.Error(w, "duplicate SSH key", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).
			Encode(map[string]any{"ssh_keys": []map[string]string{{"id": "existing", "ssh_key": material + " original-host"}}, "meta": map[string]any{"links": map[string]string{"next": ""}}})
	}))
	defer server.Close()
	api := NewVultr("test")
	api.BaseURL = server.URL
	id, err := api.EnsureSSHKey(context.Background(), "new-name", material+" replacement-host\n")
	if err != nil || id != "existing" || posts != 0 {
		t.Fatalf("same key with a different comment was registered again: id=%q posts=%d err=%v", id, posts, err)
	}
}

func TestSameSSHKeyDoesNotMatchDifferentMaterialOrMultipleKeys(t *testing.T) {
	keys := make([]string, 2)
	for i := range keys {
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, err := ssh.NewPublicKey(public)
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	}
	if sameSSHKey(keys[0]+" same-comment", keys[1]+" same-comment") {
		t.Fatal("matched different cryptographic keys")
	}
	if sameSSHKey(keys[0], keys[0]+"\n"+keys[1]) {
		t.Fatal("matched an input containing multiple keys")
	}
	if !sameSSHKey("  ssh-test public\n", "ssh-test public") {
		t.Fatal("literal malformed fixture equality changed")
	}
	if sameSSHKey("ssh-test public first", "ssh-test public second") {
		t.Fatal("normalized malformed keys instead of preserving provider validation")
	}
}

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
	source := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, http.StatusFound) }),
	)
	defer source.Close()
	v := NewVultr("test-key")
	v.BaseURL = source.URL
	if _, e := v.Instances(context.Background()); e == nil || destinationCalls != 0 {
		t.Fatal("followed redirect")
	}
}
