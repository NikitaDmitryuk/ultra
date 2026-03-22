package realitykey

import "testing"

func TestGenerate(t *testing.T) {
	p, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if p.PrivateKey == "" || p.PublicKey == "" {
		t.Fatal(p)
	}
}
