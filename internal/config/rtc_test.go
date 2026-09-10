package config

import (
	"github.com/NikitaDmitryuk/ultra/internal/rtc"
	"testing"
)

func TestRTCDisabledIgnoresPrivateFiles(t *testing.T) {
	s := &Spec{RTC: []rtc.Binding{{Enabled: true, KeyFile: "/nonexistent/secret"}}}
	in, rules, e := rtcIngress(s, nil, nil)
	if e != nil || len(in) != 0 || len(rules) != 0 {
		t.Fatal("disabled module requires private configuration", e)
	}
}
