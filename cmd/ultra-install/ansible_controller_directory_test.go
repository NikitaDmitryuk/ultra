package main

import (
	"path/filepath"
	"testing"
)

func TestManagedControllerDoesNotCollideWithLegacyRelease(t *testing.T) {
	for _, version := range []string{"v1.0.0", "v2.5.0"} {
		managed := managedControllerDirectory(version)
		legacy := filepath.Join("/opt/ultra-ansible/releases", version)
		if managed == legacy || managed != filepath.Join("/opt/ultra-ansible/releases", "managed-"+version) {
			t.Fatalf("controller namespace collides: %s", managed)
		}
		if managedControllerDirectory(version) != managed {
			t.Fatal("retry selected a new controller identity")
		}
	}
}
