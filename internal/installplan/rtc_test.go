package installplan

import (
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/rtc"
	"testing"
)

func TestRTCOverlayPreservesBindingsWithoutAliasing(t *testing.T) {
	old := &config.Spec{RTC: []rtc.Binding{{ID: "phone"}}}
	next := &config.Spec{}
	applyBridgeOverlay(next, old)
	if len(next.RTC) != 1 || next.RTC[0].ID != "phone" {
		t.Fatal("RTC lost on normal reinstall")
	}
	next.RTC[0].ID = "changed"
	if old.RTC[0].ID != "phone" {
		t.Fatal("RTC overlay aliases existing spec")
	}
}
