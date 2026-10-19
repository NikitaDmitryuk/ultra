package installplan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDatabaseTunnelKeyPinsPrivateSourceAndRejectsMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	marker := "fixture-private-material-never-serialized"
	if err := os.WriteFile(path, []byte(marker), 0600); err != nil {
		t.Fatal(err)
	}
	v := lifecycleConfigFixture()
	v["DB_TUNNEL_PRIVATE_KEY_FILE"] = path
	p, err := CanonicalValuesToPlan(v)
	if err != nil {
		t.Fatal(err)
	}
	if p.Secrets.DatabaseTunnelPrivateKeyFile != path || len(p.Secrets.DatabaseTunnelPrivateKeySHA256) != 64 {
		t.Fatal("explicit source not pinned")
	}
	raw, err := json.Marshal(p)
	if err != nil || strings.Contains(string(raw), marker) {
		t.Fatal("key material serialized")
	}
	if err := VerifyDatabaseTunnelPrivateKey(path, p.Secrets.DatabaseTunnelPrivateKeySHA256); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDatabaseTunnelPrivateKey(path, p.Secrets.DatabaseTunnelPrivateKeySHA256); err == nil {
		t.Fatal("changed identity accepted")
	}
	v["DB_TUNNEL_PRIVATE_KEY_FILE"] = filepath.Join(t.TempDir(), "unavailable")
	lifecycle, err := CanonicalLifecycleValuesToPlan(v)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(lifecycle)
	if err != nil || strings.Contains(string(raw), "database_tunnel_private_key") || lifecycle.SourceValues["DB_TUNNEL_PRIVATE_KEY_FILE"] != "" {
		t.Fatal("bootstrap private identity retained by lifecycle")
	}
}

func TestDatabaseTunnelKeyRejectsUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"relative", filepath.Join(dir, "missing"), dir, link, dir + "/../key"} {
		if _, err := DatabaseTunnelPrivateKeyDigest(path); err == nil {
			t.Fatal("unsafe source accepted")
		}
	}
	for _, mode := range []os.FileMode{0644, 0640, 0660, 0000, 0700} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := DatabaseTunnelPrivateKeyDigest(path); err == nil {
			t.Fatal("unsafe permissions accepted")
		}
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := DatabaseTunnelPrivateKeyDigest(path); err != nil {
		t.Fatal(err)
	}
	v := lifecycleConfigFixture()
	delete(v, "DATABASE_IP")
	v["DB_TUNNEL_PRIVATE_KEY_FILE"] = path
	if _, err := CanonicalValuesToPlan(v); err == nil {
		t.Fatal("preserved tunnel without primary accepted")
	}
}
