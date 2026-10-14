package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

// Seal only a freshly downloaded, fully verified release. Existing legacy trees
// are deliberately left without an ownership receipt.
func sealAutoDownload(policy autoUpgradePolicy, incoming, target string, manifest automationRelease) error {
	assets := map[string]string{}
	for _, asset := range manifest.Assets {
		assets[asset.Name] = asset.SHA
	}
	for _, name := range []string{"release-manifest.json", "release-manifest.json.minisig"} {
		raw, err := os.ReadFile(filepath.Join(incoming, name))
		if err != nil {
			return err
		}
		digest := sha256.Sum256(raw)
		assets[name] = hex.EncodeToString(digest[:])
	}
	// handoffAutoUpgrade executes this member with the same final mode. Include
	// that mode now so execution cannot invalidate the immutable inventory.
	if err := os.Chmod(filepath.Join(incoming, "ultra-install-linux-"+runtime.GOARCH), 0700); err != nil {
		return err
	}
	receipts := filepath.Join(policy.OperationLockDirectory, "retention")
	if err := ensurePrivateBootstrapDirectory(receipts); err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(target))
	receiptPath := filepath.Join(receipts, hex.EncodeToString(digest[:])+".json")
	return deployansible.WriteRetentionReceipt(incoming, target, receiptPath, map[string]any{"version": manifest.Version, "assets": assets})
}
