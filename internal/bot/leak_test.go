package bot

import "testing"

func TestUniqueStrings(t *testing.T) {
	in := []string{"1.1.1.1", "2.2.2.2", "1.1.1.1", "3.3.3.3", "2.2.2.2"}
	got := uniqueStrings(in)
	if len(got) != 3 {
		t.Fatalf("expected 3 unique values, got %d: %#v", len(got), got)
	}
}

func TestExtractUUIDIPs(t *testing.T) {
	u := "123e4567-e89b-12d3-a456-426614174000"
	src := map[string]any{
		"items": []any{
			map[string]any{
				"user": u,
				"ips":  []string{"1.1.1.1", "8.8.8.8", "1.1.1.1"},
			},
		},
	}
	out := map[string][]string{}
	extractUUIDIPs(src, out)
	ips := out[u]
	if len(ips) != 2 {
		t.Fatalf("expected 2 unique IPs for %s, got %d: %#v", u, len(ips), ips)
	}
}
