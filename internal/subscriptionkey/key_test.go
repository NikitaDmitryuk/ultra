package subscriptionkey

import (
	"encoding/base64"
	"testing"
)

func TestAuthenticatedRecovery(t *testing.T) {
	r := &Ring{Active: "v1", Keys: map[string]string{"v1": base64.StdEncoding.EncodeToString(make([]byte, 32))}}
	c, v, e := r.Seal("owner", "secret")
	if e != nil {
		t.Fatal(e)
	}
	if p, e := r.Open("owner", c, v); e != nil || p != "secret" {
		t.Fatal("recovery failed")
	}
	if _, e = r.Open("other", c, v); e == nil {
		t.Fatal("cross-owner recovery allowed")
	}
	c[len(c)-1] ^= 1
	if _, e = r.Open("owner", c, v); e == nil {
		t.Fatal("tampering allowed")
	}
	if _, e = r.Open("owner", nil, v); e == nil {
		t.Fatal("truncated ciphertext allowed")
	}
	if _, e = r.Open("owner", c, "missing"); e == nil {
		t.Fatal("unknown version allowed")
	}
	var unavailable *Ring
	if _, _, e = unavailable.Seal("owner", "secret"); e == nil {
		t.Fatal("missing key allowed")
	}
}
