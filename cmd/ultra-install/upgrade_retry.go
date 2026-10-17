package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

// Validate explicit retry authorization before runtime compensation mutates the
// previous attempt. resetFailedUpgradeAttempt performs the same check before it
// archives release stages; a live or committed attempt must never be unwound.
func requireFailedUpgradeAttempt(directory string, generation int) error {
	failed := false
	steps, err := upgradeFailedAttemptStages(directory, generation)
	if err != nil {
		return err
	}
	for _, step := range steps {
		raw, err := readBootstrapGenerationInput(filepath.Join(upgradeDependentStageDirectory(directory, step, generation), "receipt.json"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return errors.New("retry_receipt_invalid")
		}
		var receipt struct {
			State string `json:"state"`
		}
		if json.Unmarshal(raw, &receipt) != nil {
			return errors.New("retry_receipt_invalid")
		}
		if step == "commit" && receipt.State == "succeeded" {
			return errors.New("retry_operation_already_committed")
		}
		if receipt.State == "failed" || (step == "rollback" && receipt.State == "succeeded") {
			failed = true
		}
	}
	if !failed {
		return errors.New("retry_failed_operation_required")
	}
	return nil
}

// Caller must hold the operation lease and verify recovery before resetting.
// Only terminal failure receipts are reset; frozen inputs and fallbacks stay intact.
func resetFailedUpgradeAttempt(directory string) error {
	generation, err := upgradeActivationGeneration(directory, true)
	if err != nil {
		return err
	}
	// A crash after clearing activation is already a prepared next attempt.
	// Validate its immutable archive rather than advancing the attempt again.
	if _, receiptErr := os.Lstat(filepath.Join(directory, "activate", "receipt.json")); os.IsNotExist(receiptErr) && generation > 1 {
		jobRaw, jobErr := os.ReadFile(filepath.Join(directory, "activate", "job.json"))
		archivePath := filepath.Join(directory, "history", fmt.Sprintf("activate-attempt-%d.json", generation-1))
		info, archiveErr := os.Lstat(archivePath)
		if jobErr != nil || archiveErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 {
			return errors.New("retry_history_invalid")
		}
		archiveRaw, archiveErr := os.ReadFile(archivePath)
		var job, archived map[string]any
		if archiveErr != nil || json.Unmarshal(jobRaw, &job) != nil || json.Unmarshal(archiveRaw, &archived) != nil ||
			archived["request_sha256"] != job["request_sha256"] ||
			archived["binary_sha256"] != job["binary_sha256"] {
			return errors.New("retry_job_receipt_conflict")
		}
		previous := float64(1)
		if n, ok := archived["attempt"].(float64); ok {
			previous = n
		}
		if previous != float64(generation-1) || (archived["state"] != "failed" && archived["state"] != "succeeded") {
			return errors.New("retry_history_invalid")
		}
		return syncUpgradeDirectory(filepath.Join(directory, "activate"))
	}
	if err := requireFailedUpgradeAttempt(directory, generation); err != nil {
		return err
	}
	for _, step := range []string{"publish", "rollback", "commit", "activate"} {
		path := filepath.Join(upgradeDependentStageDirectory(directory, step, generation), "receipt.json")
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 {
			return errors.New("retry_receipt_invalid")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var receipt map[string]any
		if json.Unmarshal(raw, &receipt) != nil {
			return errors.New("retry_receipt_invalid")
		}
		if receipt["state"] != "failed" && receipt["state"] != "succeeded" {
			continue
		}
		var job map[string]any
		jobPath := filepath.Join(upgradeDependentStageDirectory(directory, step, generation), "job.json")
		jobInfo, err := os.Lstat(jobPath)
		if err != nil || !jobInfo.Mode().IsRegular() || jobInfo.Mode().Perm()&0077 != 0 {
			return errors.New("retry_job_invalid")
		}
		jobRaw, err := os.ReadFile(jobPath)
		if err != nil || json.Unmarshal(jobRaw, &job) != nil {
			return errors.New("retry_job_invalid")
		}
		if receipt["request_sha256"] != job["request_sha256"] || receipt["binary_sha256"] != job["binary_sha256"] {
			return errors.New("retry_job_receipt_conflict")
		}
		attempt := float64(1)
		if previous, ok := receipt["attempt"].(float64); ok {
			attempt = previous
		}
		if attempt < 1 || attempt > 999 || attempt != float64(int(attempt)) {
			return errors.New("retry_attempt_invalid")
		}
		history := filepath.Join(directory, "history")
		if err = os.MkdirAll(history, 0700); err != nil {
			return err
		}
		historyName := fmt.Sprintf("%s-attempt-%d.json", step, int(attempt))
		if step != "activate" && generation > 1 {
			historyName = fmt.Sprintf("%s-generation-%d-attempt-%d.json", step, generation, int(attempt))
		}
		if err = writeUpgradeInput(filepath.Join(history, historyName), raw); err != nil {
			return err
		}
		if err = syncUpgradeDirectory(history); err != nil {
			return err
		}
		// Timestamp-dependent jobs remain immutable in their original generation.
		// Only activation advances; the next generation gets fresh dependent jobs.
		if step != "activate" {
			continue
		}
		current := float64(1)
		if n, ok := job["attempt"].(float64); ok {
			current = n
		} else if job["attempt"] != nil {
			return errors.New("retry_attempt_invalid")
		}
		if current != attempt && current != attempt+1 {
			return errors.New("retry_attempt_conflict")
		}
		job["attempt"] = int(attempt) + 1
		data, err := json.Marshal(job)
		if err != nil {
			return err
		}
		if err = replaceUpgradeMetadata(jobPath, data); err != nil {
			return err
		}
		if err = os.Remove(path); err != nil {
			return err
		}
		if err = syncUpgradeDirectory(filepath.Dir(path)); err != nil {
			return err
		}
	}
	return nil
}
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

func clearRetriedVersionMarker(ctx context.Context, policy map[string]any, directory, version string) error {
	state, ok := policy["state_directory"].(string)
	if !ok || !filepath.IsAbs(state) {
		return nil
	}
	poller := filepath.Join(state, "poller-lock")
	if err := os.MkdirAll(poller, 0700); err != nil {
		return err
	}
	_, release, err := deployansible.WithOperationLock(ctx, poller)
	if err != nil {
		return err
	}
	defer release()
	channelFile, _ := policy["channel_state_file"].(string)
	if channelFile == "" {
		if root, okay := policy["operation_lock_directory"].(string); okay && filepath.IsAbs(root) {
			channelFile = filepath.Join(root, "channel", "state.json")
		}
	}
	if channelFile != "" {
		channel, readErr := readChannelState(channelFile)
		if readErr != nil {
			return readErr
		}
		if code := channel.Failed[version]; code != "" {
			history := filepath.Join(directory, "history")
			if err = ensurePrivateBootstrapDirectory(history); err != nil {
				return err
			}
			if err = writeUpgradeInput(filepath.Join(history, "failed-channel-block.json"), []byte(code)); err != nil {
				return err
			}
			delete(channel.Failed, version)
			data, marshalErr := json.Marshal(channel)
			if marshalErr != nil {
				return marshalErr
			}
			if err = replaceUpgradeMetadata(channelFile, data); err != nil {
				return err
			}
		}
	}
	marker := filepath.Join(state, "failed-"+version+".json")
	info, err := os.Lstat(marker)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 65536 {
		return errors.New("retry_marker_invalid")
	}
	raw, err := os.ReadFile(marker)
	if err != nil {
		return err
	}
	history := filepath.Join(directory, "history")
	if err = os.MkdirAll(history, 0700); err != nil {
		return err
	}
	if err = writeUpgradeInput(filepath.Join(history, "failed-version-marker.json"), raw); err != nil {
		return err
	}
	if err = syncUpgradeDirectory(history); err != nil {
		return err
	}
	if err = os.Remove(marker); err != nil {
		return err
	}
	return syncUpgradeDirectory(state)
}

// Activation owns the generation. A partially reset job N+1/receipt N still
// refers to generation N until its archived receipt is durably cleared.
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

// Domain stages belong to the durable generation/attempt marker. Never scan
// similarly named directories or infer the latest attempt from a failed receipt.
func upgradeFailedAttemptStages(directory string, generation int) ([]string, error) {
	steps := []string{"runtime-prepare", "runtime-apply", "runtime-rollback", "publish", "rollback", "commit", "activate"}
	raw, err := readBootstrapGenerationInput(filepath.Join(directory, fmt.Sprintf("domain-generation-%d.json", generation)))
	if os.IsNotExist(err) {
		return steps, nil
	}
	if err != nil {
		return nil, errors.New("upgrade_domain_attempt_invalid")
	}
	var marker struct {
		Version    int `json:"version"`
		Generation int `json:"generation"`
		Attempt    int `json:"attempt"`
	}
	if json.Unmarshal(raw, &marker) != nil || marker.Version != 1 || marker.Generation != generation || marker.Attempt < 1 ||
		marker.Attempt > 1000 {
		return nil, errors.New("upgrade_domain_attempt_invalid")
	}
	for _, action := range []string{"prepare", "apply", "accept", "rollback", "rollback-dns", "promote", "retire", "retire-dns"} {
		step := "domain-" + action
		if marker.Attempt > 1 {
			step += fmt.Sprintf("-attempt-%d", marker.Attempt)
		}
		steps = append(steps, step)
	}
	return steps, nil
}
