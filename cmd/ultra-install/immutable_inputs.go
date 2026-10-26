package main

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func upgradeInventory(p *installplan.InstallPlan, directory string) (map[string]any, error) {
	clone := *p
	clone.Exits = nil
	clone.Database.Enabled = false
	return bootstrapInventory(&clone, directory)
}

func writeUpgradeInput(path string, data []byte) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("upgrade_input_not_private")
		}
		previous, err := os.ReadFile(path)
		if err != nil || string(previous) != string(data) {
			return errors.New("upgrade_immutable_input_changed")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".immutable-input-")
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
	// Publish without overwriting another immutable input; failed writes never
	// leave a partial final path that could poison resume after a crash.
	if err = os.Link(name, path); err != nil {
		return err
	}
	if err = os.Remove(name); err != nil {
		return err
	}
	return syncUpgradeDirectory(filepath.Dir(path))
}
