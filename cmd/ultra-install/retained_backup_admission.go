package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func recordRetainedBackupAdmission(directory string, metadata retainedBackupMetadata, maxAge time.Duration, now time.Time) error {
	age := now.Sub(metadata.SnapshotStarted)
	if maxAge <= 0 || age > maxAge || age < -5*time.Minute {
		return errors.New("retained_primary_backup_age_invalid")
	}
	raw, err := json.Marshal(struct {
		Snapshot string  `json:"snapshot_started_utc"`
		Checked  string  `json:"checked_utc"`
		SHA256   string  `json:"backup_sha256"`
		Age      float64 `json:"age_seconds"`
		Maximum  float64 `json:"max_age_seconds"`
	}{metadata.SnapshotStarted.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339), metadata.EncryptedSHA256, age.Seconds(), maxAge.Seconds()})
	if err != nil {
		return err
	}
	if err = publishRetainedReconcile(filepath.Join(directory, "backup-admission.json"), raw); err != nil {
		return err
	}
	_, err = fmt.Fprintf(
		os.Stderr,
		"backup snapshot_started_utc=%s age=%s max_age=%s\n",
		metadata.SnapshotStarted.UTC().Format(time.RFC3339),
		age.Round(time.Second),
		maxAge,
	)
	return err
}
