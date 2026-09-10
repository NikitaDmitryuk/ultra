package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// JSON is a YAML subset. Keep the generated server fields compatible with the
// pinned strict upstream loader without starting a provider session.
func TestUltraServerConfiguration(t *testing.T) {
	root := t.TempDir()
	key := filepath.Join(root, "key")
	if err := os.WriteFile(key, []byte(strings.Repeat("a", 64)), 0600); err != nil {
		t.Fatal(err)
	}
	for _, provider := range []string{"wbstream", "telemost"} {
		data, err := json.Marshal(map[string]any{
			"mode": "srv", "auth": map[string]any{"provider": provider}, "room": map[string]any{"id": "test-room"},
			"crypto": map[string]any{"key_file": key}, "net": map[string]any{"transport": "vp8channel", "dns": "77.88.8.8:53"},
			"socks": map[string]any{"proxy_addr": "127.0.0.1", "proxy_port": 12001, "proxy_user": "phone", "proxy_pass": strings.Repeat("b", 64)},
			"vp8":   map[string]any{"fps": 30, "batch_size": 64}, "liveness": map[string]any{"interval": "10s", "timeout": "15s", "failures": 4}, "debug": false,
		})
		if err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(root, provider+".yaml")
		if err = os.WriteFile(file, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = Load(file); err != nil {
			t.Fatalf("%s configuration: %v", provider, err)
		}
	}
}
