package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAutoDownloadLogicalSourceCapacity(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"v1.0.0", "v2.0.0", "metadata", "download-crash"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := autoDownloadCapacity(root, "v3.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "v3.0.0"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := autoDownloadCapacity(root, "v3.0.0"); err != nil {
		t.Fatal("resume blocked", err)
	}
	if err := autoDownloadCapacity(root, "v4.0.0"); err == nil || err.Error() != "auto_cache_capacity_exhausted" {
		t.Fatal("fourth source admitted", err)
	}
	if _, err := os.Stat(filepath.Join(root, "v1.0.0")); err != nil {
		t.Fatal("capacity guard removed source")
	}
}

func TestAutoDownloadDiskReserve(t *testing.T) {
	var manifest automationRelease
	required, err := autoDownloadRequiredBytes(manifest)
	if err != nil || required != (1<<30)+4*(2<<20) {
		t.Fatal(required, err)
	}
	if err := autoDownloadDiskAdmission(required, required); err != nil {
		t.Fatal(err)
	}
	if err := autoDownloadDiskAdmission(required, required-1); err == nil || !strings.Contains(err.Error(), "required_bytes=") || !strings.Contains(err.Error(), "available_bytes=") {
		t.Fatal("no measured refusal", err)
	}
}
