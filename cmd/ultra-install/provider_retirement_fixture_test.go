package main

import (
	"os"
	"strings"
	"testing"
)

func retainedRebuildFixture(t *testing.T) retainedPrimaryRebuildInput {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	hosts := map[string]any{}
	for i, scope := range []struct{ group, host string }{{"bridge", "bridge"}, {"exits", "exit_0"}, {"databases", "database"}} {
		hosts[scope.group] = map[string]any{
			"hosts": map[string]any{scope.host: map[string]any{"ansible_host": []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}[i]}},
		}
	}
	hash := strings.Repeat("a", 64)
	return retainedPrimaryRebuildInput{
		Inventory: map[string]any{"all": map[string]any{"children": hosts}},
		Variables: map[string]any{
			"ultra_db_tunnel_private_key_source": "/private/preserved-key",
			"ultra_db_tunnel_private_key_sha256": hash,
		},
		JournalSHA256:              hash,
		ConfigSHA256:               hash,
		ManifestSHA256:             hash,
		CandidateMigrationsSHA256:  digestSHA256([]byte("1,2,3")),
		CandidateMigrationVersions: "1,2,3",
		FenceEvidenceSHA256:        hash,
		Primary: retainedPrimaryIdentity{
			SystemIdentifier:  "123456789",
			Database:          "app",
			DatabaseOID:       16384,
			MigrationsSHA256:  digestSHA256([]byte("1,2,3")),
			MigrationVersions: "1,2,3",
		},
		Directory:  dir,
		Python:     "/usr/bin/python3",
		Executable: "/usr/bin/ansible-playbook",
	}
}
