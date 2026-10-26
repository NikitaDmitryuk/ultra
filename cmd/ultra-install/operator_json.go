package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type retainedReconcileEvidence struct {
	RetainedExit          *retainedBridgeExit     `json:"retained_exit,omitempty"`
	Protocol              string                  `json:"protocol"`
	Fence                 string                  `json:"fence_sha256"`
	Binding               string                  `json:"binding_sha256"`
	Artifacts             map[string]string       `json:"artifacts"`
	Primary               retainedPrimaryIdentity `json:"primary"`
	ConfigureCloudRuntime bool                    `json:"configure_cloud_runtime"`
	RelayBinarySHA256     string                  `json:"relay_binary_sha256,omitempty"`
	RelayUnitSHA256       string                  `json:"relay_unit_sha256,omitempty"`
}

func decodeRetainedReconcile(raw []byte, v any) error {
	if err := retainedReconcileUniqueJSON(raw); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("retained_reconcile_json_invalid")
	}
	return nil
}

func retainedReconcileUniqueJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 128 {
			return errors.New("retained_reconcile_json_invalid")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				k, ok := key.(string)
				if !ok || seen[k] {
					return errors.New("retained_reconcile_duplicate_json_key")
				}
				seen[k] = true
				if err = value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err = value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("retained_reconcile_json_invalid")
		}
		_, err = d.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("retained_reconcile_json_invalid")
	}
	return nil
}

func publishRetainedReconcile(path string, raw []byte) error {
	if rebuildNoSymlinkAncestors(filepath.Dir(path)) != nil {
		return errors.New("retained_reconcile_receipt_unsafe")
	}
	parent := filepath.Dir(path)
	s, err := os.Lstat(parent)
	if err != nil || !s.IsDir() || s.Mode().Perm() != 0700 {
		return errors.New("retained_reconcile_private_receipt_directory_required")
	}
	owner, ok := s.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return errors.New("retained_reconcile_private_receipt_directory_required")
	}
	if _, statErr := os.Lstat(path); statErr == nil {
		old, err := readRebuildInput(path, true)
		if err != nil {
			return err
		}
		if bytes.Equal(old, raw) {
			return nil
		}
		return errors.New("retained_reconcile_receipt_conflict")
	} else if !os.IsNotExist(statErr) {
		return statErr
	}
	f, err := os.CreateTemp(parent, ".reconcile-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Link(f.Name(), path); err != nil {
		return err
	}
	if err = os.Remove(f.Name()); err != nil {
		return err
	}
	d, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
