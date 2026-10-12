package config

import "testing"

func TestSubscriptionFormatContract(t *testing.T) {
	for _, c := range []struct {
		format, transport, ua string
		flag                  bool
		want                  string
		fail                  bool
	}{
		{"", "", "Happ/3 Android", false, "uri", false},
		{"", "", "Happ/3 Android", true, "happ", false},
		{"", "", "Mozilla Happier/3", true, "uri", false},
		{"", "", "Other/1", true, "uri", false},
		{"uri", "", "Happ/3", true, "uri", false},
		{"happ", "", "Other", false, "happ", false},
		{"", "xhttp-tls", "Happ/3", true, "uri", false},
		{"happ", "xhttp-tls", "Happ/3", true, "", true},
		{"bad", "", "", true, "", true},
	} {
		got, err := ResolveSubscriptionFormat(c.format, c.transport, c.ua, c.flag)
		if got != c.want || (err != nil) != c.fail {
			t.Fatalf("%+v: got %q %v", c, got, err)
		}
	}
}
