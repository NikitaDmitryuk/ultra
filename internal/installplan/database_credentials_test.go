package installplan

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestFreshBridgeCanReusePreservedDedicatedDatabaseCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "saved-spec.json")
	if err := os.WriteFile(path, []byte(`{"database":{"dsn":"postgres://ultra:preserved-fixture-p%40ss%2F%3F%23@127.0.0.1:25432/ultra_db?sslmode=disable"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	p := LegacyValuesToPlan(map[string]string{"BRIDGE_IP": "192.0.2.10", "MAIN_EXIT_IP": "192.0.2.20", "DATABASE_IP": "192.0.2.40", "DB_CREDENTIALS_FILE": path, "REUSE_BRIDGE_SPEC": "false", "REALITY_DEST": "example.com:443"})
	first, err := RenderDesiredState(p)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderDesiredState(p)
	if err != nil {
		t.Fatal(err)
	}
	if first.PostgresConfig.DBPassword != "preserved-fixture-p@ss/?#" || first.DBDSN != second.DBDSN {
		t.Fatal("reinstallation rotated existing database credentials")
	}
	u, err := url.Parse(first.DBDSN)
	if err != nil || u.User == nil {
		t.Fatal("invalid preserved connection URI")
	}
	password, _ := u.User.Password()
	if password != "preserved-fixture-p@ss/?#" {
		t.Fatal("preserved credentials were not URI escaped")
	}
	if p.Secrets.DatabaseCredentialsFile != path {
		t.Fatal("credential reference lost")
	}
}

func TestDatabaseCredentialsRejectPublicSymlinkAndWrongIdentity(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "spec.json")
	if err := os.WriteFile(path, []byte(`{"database":{"dsn":"postgres://other:fixture@127.0.0.1:25432/other"}}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDatabaseCredentials(path); err == nil {
		t.Fatal("public credentials accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDatabaseCredentials(link); err == nil {
		t.Fatal("symlink credentials accepted")
	}
	p := LegacyValuesToPlan(map[string]string{"BRIDGE_IP": "192.0.2.10", "MAIN_EXIT_IP": "192.0.2.20", "DATABASE_IP": "192.0.2.40", "DB_CREDENTIALS_FILE": path, "REUSE_BRIDGE_SPEC": "false", "REALITY_DEST": "example.com:443"})
	if _, err := RenderDesiredState(p); err == nil {
		t.Fatal("wrong database identity accepted")
	}
}
