package install

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEmbeddedSystemdUnitsMatchDeployFiles(t *testing.T) {
	cases := []struct {
		name     string
		embedded string
		deploy   string
	}{
		{
			name:     "relay",
			embedded: RelaySystemdUnit,
			deploy:   filepath.Join("..", "..", "deploy", "systemd", "ultra-relay.service"),
		},
		{
			name:     "bot",
			embedded: BotSystemdUnit,
			deploy:   filepath.Join("..", "..", "deploy", "systemd", "ultra-bot.service"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := os.ReadFile(tc.deploy)
			if err != nil {
				t.Fatal(err)
			}
			if tc.embedded != string(want) {
				t.Fatalf("embedded systemd unit differs from %s", tc.deploy)
			}
		})
	}
}
