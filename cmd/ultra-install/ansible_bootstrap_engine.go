package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Existing attempts without an engine marker retain their original playbook.
// The choice is frozen before application, rather than inferred from partial files.
func bootstrapUsesComponents(directory string) (bool, error) {
	raw, err := readBootstrapGenerationInput(filepath.Join(directory, "execution-mode.json"))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var mode frozenExecution
	if json.Unmarshal(raw, &mode) != nil || mode.Schema != 1 {
		return false, errors.New("bootstrap_engine_invalid")
	}
	switch mode.BootstrapEngine {
	case "":
		return false, nil
	case "components-v1":
		if _, err := os.Lstat(filepath.Join(directory, "apply", "job.json")); err == nil {
			return false, errors.New("bootstrap_engine_conflicts_with_legacy_job")
		} else if !os.IsNotExist(err) {
			return false, err
		}
		return true, nil
	default:
		return false, errors.New("bootstrap_engine_unsupported")
	}
}
