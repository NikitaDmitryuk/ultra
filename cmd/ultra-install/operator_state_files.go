package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func replaceUpgradeMetadata(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), "metadata-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name) //nolint:errcheck
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	return syncUpgradeDirectory(filepath.Dir(path))
}

func syncUpgradeDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close() //nolint:errcheck
	return directory.Sync()
}

func upgradeActivationGeneration(directory string, resetting bool) (int, error) {
	path := filepath.Join(directory, "activate", "job.json")
	if resetting {
		if _, err := os.Lstat(filepath.Join(directory, "activate", "receipt.json")); err == nil {
			path = filepath.Join(directory, "activate", "receipt.json")
		} else if !os.IsNotExist(err) {
			return 0, err
		}
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return 1, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 {
		return 0, errors.New("retry_generation_invalid")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var metadata map[string]any
	if json.Unmarshal(raw, &metadata) != nil {
		return 0, errors.New("retry_generation_invalid")
	}
	if metadata["attempt"] == nil {
		return 1, nil
	}
	n, ok := metadata["attempt"].(float64)
	if !ok || n < 1 || n > 1000 || n != float64(int(n)) {
		return 0, errors.New("retry_generation_invalid")
	}
	return int(n), nil
}

func upgradeDependentStageDirectory(directory, step string, generation int) string {
	if step == "activate" || generation == 1 {
		return filepath.Join(directory, step)
	}
	return filepath.Join(directory, fmt.Sprintf("%s-generation-%d", step, generation))
}
