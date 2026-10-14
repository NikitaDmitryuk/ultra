package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
	"os"
	"path/filepath"
	"testing"
)

func TestOfflineRuntimeArchiveBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, member string
		kind         byte
		valid        bool
	}{
		{"lock", "requirements.lock", tar.TypeReg, true},
		{"wheel", "wheels/package.whl", tar.TypeReg, true},
		{"escape", "../outside", tar.TypeReg, false},
		{"nested", "wheels/../package.whl", tar.TypeReg, false},
		{"link", "wheels/package.whl", tar.TypeSymlink, false},
		{"unexpected", "install.sh", tar.TypeReg, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			source := filepath.Join(directory, "runtime.tar.gz")
			file, err := os.Create(source)
			if err != nil {
				t.Fatal(err)
			}
			zip := gzip.NewWriter(file)
			archive := tar.NewWriter(zip)
			header := &tar.Header{Name: tc.member, Typeflag: tc.kind, Size: 4, Mode: 0600}
			if tc.kind == tar.TypeSymlink {
				header.Size = 0
				header.Linkname = "/etc/passwd"
			}
			if err := archive.WriteHeader(header); err != nil {
				t.Fatal(err)
			}
			if header.Size > 0 {
				if _, err := archive.Write([]byte("data")); err != nil {
					t.Fatal(err)
				}
			}
			if err := archive.Close(); err != nil {
				t.Fatal(err)
			}
			if err := zip.Close(); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			err = extractRuntime(source, filepath.Join(directory, "extracted"))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
			if tc.valid {
				if err := extractRuntime(source, filepath.Join(directory, "extracted")); err != nil {
					t.Fatal("idempotent extraction", err)
				}
			}
		})
	}
}

func TestOfflineRuntimeFromExplicitFixture(t *testing.T) {
	release := os.Getenv("ULTRA_TEST_OFFLINE_RELEASE")
	if release == "" {
		t.Skip("requires explicit isolated release fixture")
	}
	manifest, err := verifyAutomationRelease(release, "")
	if err != nil {
		t.Fatal(err)
	}
	plan := &installplan.InstallPlan{Automation: &installplan.AutomationConfig{ReleaseDir: release, Version: manifest.Version}}
	root := t.TempDir()
	first, err := resolveAnsibleRuntime(context.Background(), plan, root, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := resolveAnsibleRuntime(context.Background(), plan, root, "")
	if err != nil || first != second {
		t.Fatal("runtime reuse failed", err)
	}
}

func TestInstalledRuntimeMustMatchTargetDependencyHash(t *testing.T) {
	directory := t.TempDir()
	binary := filepath.Join(directory, "ansible-playbook")
	marker := filepath.Join(directory, "runtime.sha256")
	if err := os.WriteFile(binary, []byte("fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte("previous\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if installedRuntimeMatches(binary, marker, "target") {
		t.Fatal("previous runtime reused for target dependency set")
	}
	if err := os.WriteFile(marker, []byte("target\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if !installedRuntimeMatches(binary, marker, "target") {
		t.Fatal("confirmed target runtime rejected")
	}
	if err := os.Chmod(marker, 0644); err != nil {
		t.Fatal(err)
	}
	if installedRuntimeMatches(binary, marker, "target") {
		t.Fatal("unprotected runtime identity accepted")
	}
}

func TestRecoveryRuntimeRejectsChecksumBeforePreparingPrivateState(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "runtime.tar.gz")
	if err := os.WriteFile(archive, []byte("synthetic archive"), 0600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "state")
	if _, err := preparePinnedAnsibleRuntime(context.Background(), state, archive, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err == nil {
		t.Fatal("unchecked archive accepted")
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("state changed before checksum validation")
	}
	link := filepath.Join(root, "link.tar.gz")
	if err := os.Symlink(archive, link); err != nil {
		t.Fatal(err)
	}
	hash, err := sourceSHA(archive)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := preparePinnedAnsibleRuntime(context.Background(), state, link, hash); err == nil {
		t.Fatal("symlink runtime source accepted")
	}
}
