package mimic

import (
	"strings"
	"testing"
)

func TestPlusGamingHostAndHeaders(t *testing.T) {
	p := NewPlusGaming()
	if p.Host() != "gw.cg.yandex.ru" {
		t.Fatal(p.Host())
	}
	h := p.ExtraHeaders()
	if h["Origin"] != "https://plusgaming.yandex.ru" {
		t.Fatal(h["Origin"])
	}
	if h["Accept"] != "application/json" {
		t.Fatal(h["Accept"])
	}
}

func TestPlusGamingPathShape(t *testing.T) {
	p := NewPlusGaming()
	for range 200 {
		path := p.NextPath()
		if !strings.HasPrefix(path, "/api/") {
			t.Fatalf("expected /api/ prefix: %q", path)
		}
	}
}

func TestNewPreset(t *testing.T) {
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
