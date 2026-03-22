package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSpecRequiresGeoDatFiles(t *testing.T) {
	root := t.TempDir()
	geoDir := filepath.Join(root, "geo")
	if err := os.MkdirAll(geoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		if err := os.WriteFile(filepath.Join(geoDir, name), []byte("stub"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	usersPath := filepath.Join(root, "users.json")
	if err := os.WriteFile(usersPath, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	absUsers, _ := filepath.Abs(usersPath)
	absGeo, _ := filepath.Abs(geoDir)
	usersJ, _ := json.Marshal(absUsers)
	geoJ, _ := json.Marshal(absGeo)
	specPath := filepath.Join(root, "spec.json")
	specJSON := `{
  "schema_version": 1,
  "role": "bridge",
  "dev_mode": true,
  "mimic_preset": "apijson",
  "users_path": ` + string(usersJ) + `,
  "listen_address": "127.0.0.1",
  "vless_port": 443,
  "public_host": "127.0.0.1",
  "reality": {},
  "exit": {"address":"10.0.0.2","port":443,"tunnel_uuid":"11111111-2222-3333-4444-555555555555"},
  "splithttp_path": "/p",
  "splithttp_tls": {"server_name":"x","alpn":["h2"],"fingerprint":"chrome"},
  "exit_cert": {},
  "geo_assets_dir": ` + string(geoJ) + `
}`
	if err := os.WriteFile(specPath, []byte(specJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSpec(specPath); err != nil {
		t.Fatal(err)
	}
}

func TestLoadSpecMissingGeoFileFails(t *testing.T) {
	root := t.TempDir()
	geoDir := filepath.Join(root, "geo")
	if err := os.MkdirAll(geoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(geoDir, "geoip.dat"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	usersPath := filepath.Join(root, "users.json")
	if err := os.WriteFile(usersPath, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	absUsers2, _ := filepath.Abs(usersPath)
	absGeo2, _ := filepath.Abs(geoDir)
	usersJ2, _ := json.Marshal(absUsers2)
	geoJ2, _ := json.Marshal(absGeo2)
	specPath := filepath.Join(root, "spec.json")
	specJSON := `{
  "schema_version": 1,
  "role": "bridge",
  "dev_mode": true,
  "mimic_preset": "apijson",
  "users_path": ` + string(usersJ2) + `,
  "listen_address": "127.0.0.1",
  "vless_port": 443,
  "public_host": "127.0.0.1",
  "reality": {},
  "exit": {"address":"10.0.0.2","port":443,"tunnel_uuid":"11111111-2222-3333-4444-555555555555"},
  "splithttp_path": "/p",
  "splithttp_tls": {"server_name":"x","alpn":["h2"],"fingerprint":"chrome"},
  "exit_cert": {},
  "geo_assets_dir": ` + string(geoJ2) + `
}`
	if err := os.WriteFile(specPath, []byte(specJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSpec(specPath); err == nil {
		t.Fatal("expected error when geosite.dat is missing")
	}
}
