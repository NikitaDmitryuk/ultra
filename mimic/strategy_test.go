package mimic

import (
	"strings"
	"testing"
)

func TestAPIJSONHostAndHeaders(t *testing.T) {
	p := NewAPIJSON()
	if p.Host() != DefaultSplithttpHost {
		t.Fatal(p.Host())
	}
	h := p.ExtraHeaders()
	wantOrigin := "https://" + DefaultSplithttpHost
	if h["Origin"] != wantOrigin {
		t.Fatal(h["Origin"])
	}
	if h["Accept"] != "application/json" {
		t.Fatal(h["Accept"])
	}
}

func TestAPIJSONPathShape(t *testing.T) {
	p := NewAPIJSON()
	for range 200 {
		path := p.NextPath()
		if !strings.HasPrefix(path, "/api/") {
			t.Fatalf("expected /api/ prefix: %q", path)
		}
	}
}

func TestNewPreset(t *testing.T) {
	if _, err := New("apijson"); err != nil {
		t.Fatal(err)
	}
	if _, err := New("plusgaming"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(""); err != nil {
		t.Fatal(err)
	}
	if _, err := New("nope"); err == nil {
		t.Fatal("expected error")
	}
}
