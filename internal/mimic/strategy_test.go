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
	if _, err := New("steamlike"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(""); err != nil {
		t.Fatal(err)
	}
	if _, err := New("nope"); err == nil {
		t.Fatal("expected error")
	}
}

func TestSteamlikeHostAndHeaders(t *testing.T) {
	p := NewSteamlike()
	if p.Host() != DefaultSteamlikeHost {
		t.Fatal(p.Host())
	}
	h := p.ExtraHeaders()
	if h["Accept"] != "*/*" {
		t.Fatal(h["Accept"])
	}
	if !strings.Contains(h["User-Agent"], "Steam") {
		t.Fatal(h["User-Agent"])
	}
}

func TestSteamlikePathShape(t *testing.T) {
	p := NewSteamlike()
	for range 300 {
		path := p.NextPath()
		if !strings.HasPrefix(path, "/") {
			t.Fatalf("expected leading slash: %q", path)
		}
		if strings.Contains(path, " ") {
			t.Fatalf("unexpected space: %q", path)
		}
	}
}
