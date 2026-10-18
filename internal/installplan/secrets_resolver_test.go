package installplan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDoctorUsesInvocationSecretResolver(t *testing.T) {
	p := completePlanFixture(&InstallPlan{
		SSH:      SSHConfig{User: "root"},
		Bridge:   BridgeConfig{SSHHost: "203.0.113.10", RealityDest: "www.example.com:443"},
		Exits:    []ExitNode{{Name: "primary", SSHHost: "203.0.113.11"}},
		Features: FeatureConfig{Preset: "apijson", Transport: "splithttp", LogLevel: "info", GenerateExitTLS: true},
		Secrets:  SecretsConfig{EnvFile: "not-staged.env"},
	})
	root := t.TempDir()
	p.SecretResolver = func() (map[string]string, error) { return map[string]string{"TELEGRAM_BOT_TOKEN": "fixture"}, nil }
	if report := Doctor(context.Background(), p, DoctorOptions{EnvRoot: root}); !report.OK {
		t.Fatalf("resolver doctor failed: %#v", report.Issues)
	}
	p.SecretResolver = func() (map[string]string, error) { return nil, errors.New("installed_runtime_secrets_untrusted") }
	if report := Doctor(context.Background(), p, DoctorOptions{EnvRoot: root}); report.OK || len(report.Issues) != 1 ||
		report.Issues[0].Message != "installed_runtime_secrets_untrusted" {
		t.Fatal("resolver failure was not preserved")
	}
	if _, err := os.Stat(filepath.Join(root, "not-staged.env")); !os.IsNotExist(err) {
		t.Fatal("created canonical file")
	}
}
