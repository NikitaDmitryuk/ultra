package main

import "testing"

func TestPublicURL(t *testing.T) {
	for _, tt := range []struct {
		override, domain, port, want string
		dev                          bool
	}{
		{"", "bot.example", "8444", "https://bot.example:8444/", false},
		{"", "bot.example", "443", "https://bot.example/", false},
		{"", "localhost", "80", "http://localhost/", true},
		{"", "", "8444", "", false},
		{"https://bot.example", "old.example", "8444", "https://bot.example/", false},
		{"https://bot.example:9443/", "old.example", "8444", "https://bot.example:9443/", false},
	} {
		got, err := resolvePublicURL(tt.override, tt.domain, tt.port, tt.dev)
		if err != nil || got != tt.want {
			t.Fatalf("got %q, %v; want %q", got, err, tt.want)
		}
	}
	for _, input := range []string{"http://bot.example", "https://user:secret@bot.example", "https://bot.example/path", "https://bot.example?secret=x", "https://bot.example#secret", "https://bot.example?", "https:///", "invalid"} {
		if _, err := resolvePublicURL(input, "", "8444", false); err == nil {
			t.Fatalf("accepted invalid origin")
		}
	}
}
