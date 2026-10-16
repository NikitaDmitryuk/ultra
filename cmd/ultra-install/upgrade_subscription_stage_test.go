package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func writeTestSubscriptionKeyring(t *testing.T, path string, raw string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareUpgradeSubscriptionStageRejectsUnsafeExistingStage(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "keys.json")
	raw := `{"active":"v1","keys":{"v1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`
	writeTestSubscriptionKeyring(t, source, raw)
	plan := subscriptionPlan(source)

	t.Run("symlink", func(t *testing.T) {
		operation := filepath.Join(root, "symlink-op")
		stageDir := upgradeDependentStageDirectory(operation, "subscription-keys", 1)
		if err := os.MkdirAll(stageDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(source, filepath.Join(stageDir, "keyring.json")); err != nil {
			t.Fatal(err)
		}
		if _, _, err := prepareUpgradeSubscriptionStage(plan, operation, 1); err == nil {
			t.Fatal("accepted staged symlink")
		}
	})
	t.Run("hardlink", func(t *testing.T) {
		operation := filepath.Join(root, "hardlink-op")
		stageDir := upgradeDependentStageDirectory(operation, "subscription-keys", 1)
		if err := os.MkdirAll(stageDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(source, filepath.Join(stageDir, "keyring.json")); err != nil {
			t.Fatal(err)
		}
		if _, _, err := prepareUpgradeSubscriptionStage(plan, operation, 1); err == nil {
			t.Fatal("accepted staged hardlink")
		}
	})
	t.Run("foreign-owner", func(t *testing.T) {
		operation := filepath.Join(root, "foreign-op")
		stageDir := upgradeDependentStageDirectory(operation, "subscription-keys", 1)
		if err := os.MkdirAll(stageDir, 0700); err != nil {
			t.Fatal(err)
		}
		stage := filepath.Join(stageDir, "keyring.json")
		if err := os.WriteFile(stage, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Chown(stage, int(os.Geteuid()+1), -1); err != nil {
			t.Skipf("cannot create foreign-owned fixture: %v", err)
		}
		if _, _, err := prepareUpgradeSubscriptionStage(plan, operation, 1); err == nil {
			t.Fatal("accepted foreign-owned staged file")
		}
	})
}

func TestPrepareUpgradeSubscriptionStageCleanupPreservesSourceIdentity(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "keys.json")
	writeTestSubscriptionKeyring(t, source, `{"active":"v1","keys":{"v1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`)
	operation := filepath.Join(root, "operation")
	stage, cleanup, err := prepareUpgradeSubscriptionStage(subscriptionPlan(source), operation, 1)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := filepath.Join(filepath.Dir(stage), "source.sha256")
	if err = cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(stage); !os.IsNotExist(err) {
		t.Fatalf("secret stage remains after cleanup: %v", err)
	}
	if _, err = os.Stat(fingerprint); err != nil {
		t.Fatalf("source fingerprint not retained: %v", err)
	}
	writeTestSubscriptionKeyring(t, source, `{"active":"v2","keys":{"v2":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`)
	if _, _, err = prepareUpgradeSubscriptionStage(subscriptionPlan(source), operation, 1); err == nil ||
		!strings.Contains(err.Error(), "changed") {
		t.Fatalf("retry after cleanup accepted changed source: %v", err)
	}
}

func subscriptionPlan(path string) *installplan.InstallPlan {
	return &installplan.InstallPlan{SourceValues: map[string]string{"ULTRA_SUBSCRIPTION_ENCRYPTION_KEY_FILE": path}}
}

func TestPrepareUpgradeSubscriptionStage(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "keys.json")
	raw := `{"active":"v1","keys":{"v1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`
	writeTestSubscriptionKeyring(t, source, raw)
	operation := filepath.Join(root, "operation")
	stage, cleanup, err := prepareUpgradeSubscriptionStage(subscriptionPlan(source), operation, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cleanup() }()
	got, err := os.ReadFile(stage)
	if err != nil || string(got) != raw {
		t.Fatalf("staged bytes differ: %v", err)
	}
	info, err := os.Stat(stage)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("stage permissions: %v %v", info, err)
	}
	stage2, cleanup2, err := prepareUpgradeSubscriptionStage(subscriptionPlan(source), operation, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cleanup2() }()
	if stage != stage2 {
		t.Fatalf("retry staged at %q, want %q", stage2, stage)
	}
	writeTestSubscriptionKeyring(t, source, `{"active":"v2","keys":{"v2":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`)
	if _, _, err = prepareUpgradeSubscriptionStage(subscriptionPlan(source), operation, 2); err == nil ||
		!strings.Contains(err.Error(), "changed") {
		t.Fatalf("changed keyring was accepted: %v", err)
	}
}

func TestPrepareUpgradeSubscriptionStageOptionalAndRejectsUnsafeSources(t *testing.T) {
	if path, cleanup, err := prepareUpgradeSubscriptionStage(&installplan.InstallPlan{}, t.TempDir(), 1); err != nil || path != "" ||
		cleanup != nil {
		t.Fatalf("absent keyring: path=%q cleanup-present=%t err=%v", path, cleanup != nil, err)
	}
	root := t.TempDir()
	source := filepath.Join(root, "keys.json")
	writeTestSubscriptionKeyring(t, source, `{"active":"v1","keys":{"v1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`)
	if err := os.Chmod(source, 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := prepareUpgradeSubscriptionStage(subscriptionPlan(source), filepath.Join(root, "op"), 1); err == nil {
		t.Fatal("accepted non-private source")
	}
	if err := os.Chmod(source, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.json")
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := prepareUpgradeSubscriptionStage(subscriptionPlan(link), filepath.Join(root, "op"), 1); err == nil {
		t.Fatal("accepted symlink source")
	}
	if err := os.Link(source, filepath.Join(root, "hardlink.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := readSubscriptionKeyringSource(source); err == nil {
		t.Fatal("accepted multiply-linked source")
	}
}

func TestValidateSubscriptionKeyringRejectsInvalidRings(t *testing.T) {
	valid := `{"active":"v1","keys":{"v1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`
	for _, raw := range []string{
		`{"active":"v2","keys":{"v1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`,
		`{"active":"v1","keys":{"bad id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`,
		`{"active":"v1","keys":{"v1":"AA=="}}`,
		`{"active":"v1","active":"v1","keys":{"v1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`,
		`{"active":"v1","keys":{"v1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","v1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`,
		`{"active":"v1","keys":{"v1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"extra":true}`,
	} {
		if err := validateSubscriptionKeyring([]byte(raw)); err == nil {
			t.Fatalf("accepted invalid ring: %s", raw)
		}
	}
	if err := validateSubscriptionKeyring([]byte(valid)); err != nil {
		t.Fatalf("rejected valid ring: %v", err)
	}
}
