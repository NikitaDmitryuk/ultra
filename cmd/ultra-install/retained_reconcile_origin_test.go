package main

import (
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestRetainedReconcileUsesPublicMiniAppOrigin(t *testing.T) {
	p := &installplan.InstallPlan{
		Bot:          installplan.BotConfig{Domain: "bot.example.com"},
		SourceValues: map[string]string{"BOT_PUBLIC_URL": "https://sync.example.com"},
	}
	host, err := retainedReconcileBotHost(p)
	if err != nil || host != "sync.example.com" {
		t.Fatalf("public ingress identity lost: %q, %v", host, err)
	}
	for _, value := range []string{"http://sync.example.com", "https://user:password@sync.example.com", "https://sync.example.com:8444"} {
		p.SourceValues["BOT_PUBLIC_URL"] = value
		if _, err := retainedReconcileBotHost(p); err == nil {
			t.Fatal("unsupported origin accepted")
		}
	}
}
