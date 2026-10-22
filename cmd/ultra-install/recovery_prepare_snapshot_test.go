package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestRecoveryPreparationFleetIdentityAllowsPublicKeyComment(t *testing.T) {
	root := filepath.Join(t.TempDir(), "ultra-fleet")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	for name, mode := range map[string]os.FileMode{"id_ed25519": 0600, "id_ed25519.pub": 0644} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("fixture"), mode); err != nil {
			t.Fatal(err)
		}
	}
	keygen := filepath.Join(t.TempDir(), "ssh-keygen")
	program := strings.ReplaceAll(recoveryPreparationFleetIdentityProgram, "Path('/etc/ultra-fleet')", "Path("+strconv.Quote(root)+")")
	program = strings.ReplaceAll(program, "'/usr/bin/ssh-keygen'", strconv.Quote(keygen))
	program = strings.ReplaceAll(program, "for path in [root,*root.parents]:", "for path in [root]:")
	program = strings.ReplaceAll(program, "info.st_uid==0", "info.st_uid==os.geteuid()")
	program = strings.ReplaceAll(program, "allowed={0,pwd.getpwnam('ultra-relay').pw_uid}", "allowed={os.geteuid()}")
	if strings.Contains(program, "Path('/etc/ultra-fleet')") || strings.Contains(program, "info.st_uid==0") {
		t.Fatal("test fixture did not isolate host-specific checks")
	}
	for _, tc := range []struct {
		name, generated, published string
		wantSuccess                bool
	}{
		{"commented key", "ssh-ed25519 Zml4dHVyZQ== host-comment", "ssh-ed25519 Zml4dHVyZQ== published-comment", true},
		{"uncommented key", "ssh-ed25519 Zml4dHVyZQ==", "ssh-ed25519 Zml4dHVyZQ==", true},
		{"different key", "ssh-ed25519 ZGlmZmVyZW50", "ssh-ed25519 Zml4dHVyZQ==", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pub := []byte(tc.published + "\n")
			if err := os.WriteFile(filepath.Join(root, "id_ed25519.pub"), pub, 0644); err != nil {
				t.Fatal(err)
			}
			stub := "#!/bin/sh\nprintf '%s\\n' " + strconv.Quote(tc.generated) + "\n"
			if err := os.WriteFile(keygen, []byte(stub), 0700); err != nil {
				t.Fatal(err)
			}
			err := exec.Command("python3", "-I", "-c", program).Run()
			if (err == nil) != tc.wantSuccess {
				t.Fatalf("fleet public key validation success=%v, want %v: %v", err == nil, tc.wantSuccess, err)
			}
		})
	}
}

func TestRecoveryPreparationRelocationPreservesHistoricalBinding(t *testing.T) {
	in, original := reconcileFixture(t)
	_, before, err := loadRetainedReconcile(original[0], original[1], original[2], original[3])
	if err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(t.TempDir(), "retained")
	if err = os.Rename(original[0], snapshot); err != nil {
		t.Fatal(err)
	}
	config, manifest, journal := filepath.Join(snapshot, "config"), filepath.Join(snapshot, "manifest"), filepath.Join(snapshot, "journal")
	if _, _, err = loadRetainedReconcile(snapshot, config, manifest, journal); err == nil {
		t.Fatal("historical verifier silently accepted relocated paths")
	}
	restored, after, err := loadRetainedReconcileSnapshot(snapshot, config, manifest, journal, in.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Directory != in.Directory || before.Binding != after.Binding ||
		before.Artifacts["prepared"] != after.Artifacts["prepared"] {
		t.Fatal("relocation rewrote historical evidence")
	}
	if _, _, err = loadRetainedReconcileSnapshot(snapshot, config, manifest, journal, filepath.Dir(in.Directory)); err == nil {
		t.Fatal("different logical source accepted")
	}
	if err = os.WriteFile(filepath.Join(snapshot, "execute", "bundle", "controller.py"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = loadRetainedReconcileSnapshot(snapshot, config, manifest, journal, in.Directory); err == nil {
		t.Fatal("changed physical bundle accepted")
	}
}

func TestRecoveryPreparationRelayRelocationAuthenticatesLogicalAndPhysicalSources(t *testing.T) {
	physical := t.TempDir()
	logicalRelease := "/original/release"
	release := filepath.Join(physical, "release")
	evidence := filepath.Join(physical, "retained")
	unitPath := filepath.Join(evidence, "execute/bundle/roles/relay/templates/ultra-relay.service.j2")
	if err := os.MkdirAll(filepath.Dir(unitPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(release, 0700); err != nil {
		t.Fatal(err)
	}
	unit := []byte("[Service]\nExecStart=/usr/local/bin/ultra-relay -require-provider-pool-quota -spec /etc/ultra-relay/spec.json\n")
	if err := os.WriteFile(unitPath, unit, 0600); err != nil {
		t.Fatal(err)
	}
	image := []byte("fixture compiled baseline relay")
	name := "ultra-relay-linux-amd64"
	if err := os.WriteFile(filepath.Join(release, name), image, 0700); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"schema_version": 1, "database_schema_max": 1,
		"assets": []map[string]any{{"name": name, "sha256": digestSHA256(image), "size": len(image)}}})
	manifest := filepath.Join(release, "release-manifest.json")
	if err := os.WriteFile(manifest, raw, 0600); err != nil {
		t.Fatal(err)
	}
	in := retainedPrimaryRebuildInput{Directory: "/original/retained", ManifestSHA256: digestSHA256(raw), CandidateMigrationVersions: "1",
		Inventory: map[string]any{"all": map[string]any{"children": map[string]any{"bridge": map[string]any{"hosts": map[string]any{
			"bridge": map[string]any{"ultra_relay_source": filepath.Join(logicalRelease, name), "ultra_relay_sha256": digestSHA256(image)},
		}}}}}}
	if _, _, err := retainedReconcileRelayIdentity(in, manifest); err == nil {
		t.Fatal("historical verifier accepted a different source root")
	}
	sha, unitSHA, err := retainedReconcileRelayIdentitySnapshot(in, manifest, logicalRelease, evidence)
	if err != nil || sha != digestSHA256(image) || unitSHA != digestSHA256(unit) {
		t.Fatalf("snapshot identity rejected: %v", err)
	}
	if _, _, err = retainedReconcileRelayIdentitySnapshot(in, manifest, "/other/release", evidence); err == nil {
		t.Fatal("different logical relay source accepted")
	}
	if err = os.WriteFile(filepath.Join(release, name), []byte("changed"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err = retainedReconcileRelayIdentitySnapshot(in, manifest, logicalRelease, evidence); err == nil {
		t.Fatal("different physical relay image accepted")
	}
}
