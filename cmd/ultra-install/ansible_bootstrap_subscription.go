package main

import (
	"errors"
	"path/filepath"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// The frozen inventory decides whether this attempt delivers a keyring. In
// particular, adding a configured source must not rewrite an older request.
// Keep generation one across compatible rollback: the inventory and keyring
// fingerprint belong to the whole bootstrap attempt.
func prepareFrozenBootstrapSubscription(p *installplan.InstallPlan, inventory map[string]any, directory string) (func() error, error) {
	all, _ := inventory["all"].(map[string]any)
	children, _ := all["children"].(map[string]any)
	group, _ := children["bridge"].(map[string]any)
	hosts, _ := group["hosts"].(map[string]any)
	bridge, _ := hosts["bridge"].(map[string]any)
	value, exists := bridge["ultra_upgrade_subscription_key_source"]
	if !exists {
		return nil, nil
	}
	expected := filepath.Join(upgradeDependentStageDirectory(directory, "subscription-keys", 1), "keyring.json")
	if source, ok := value.(string); !ok || source != expected {
		return nil, errors.New("bootstrap_subscription_stage_invalid")
	}
	source, cleanup, err := prepareUpgradeSubscriptionStage(p, directory, 1)
	if err != nil {
		return nil, err
	}
	if source != expected {
		return nil, errors.New("bootstrap_subscription_source_required")
	}
	return cleanup, nil
}
