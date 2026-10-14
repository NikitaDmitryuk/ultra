package main

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
)

// Source releases are bounded independently of durable job history. Unknown
// version directories count toward capacity but are never adopted or removed.
func autoDownloadCapacity(directory, version string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	count := 0
	present := false
	for _, entry := range entries {
		if !stableVersion(entry.Name()) {
			continue
		}
		info, err := os.Lstat(filepath.Join(directory, entry.Name()))
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return errors.New("auto_cache_version_path_invalid")
		}
		count++
		if entry.Name() == version {
			present = true
		}
	}
	if !present {
		count++
	}
	if count > 3 {
		return errors.New("auto_cache_capacity_exhausted")
	}
	return nil
}

// Reserve 1 GiB for host/state growth in addition to four times compressed
// release bytes for download, unpacking and installation copies. This is a
// conservative admission check, not a guarantee about other mounted volumes.
func autoDownloadRequiredBytes(manifest automationRelease) (uint64, error) {
	const reserve uint64 = 1 << 30
	total := uint64(2 << 20) // bounded manifest and signature downloads
	for _, asset := range manifest.Assets {
		if asset.Size <= 0 || asset.Size > 256<<20 {
			return 0, errors.New("auto_asset_metadata_invalid")
		}
		if uint64(asset.Size) > (math.MaxUint64-reserve)/4-total {
			return 0, errors.New("auto_asset_metadata_invalid")
		}
		total += uint64(asset.Size)
	}
	return reserve + 4*total, nil
}

func autoDownloadDiskAdmission(required, available uint64) error {
	if available < required {
		return fmt.Errorf("auto_cache_free_space_insufficient: required_bytes=%d available_bytes=%d", required, available)
	}
	return nil
}
