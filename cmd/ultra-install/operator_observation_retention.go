package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type retiredOperatorObservation struct {
	Schema           int    `json:"schema"`
	OperationID      string `json:"operation_id"`
	Stage            string `json:"stage_directory"`
	RequestSHA       string `json:"request_sha256"`
	ReceiptSHA       string `json:"receipt_sha256"`
	Winner           string `json:"winning_stage"`
	WinnerRequestSHA string `json:"winning_request_sha256"`
	WinnerReceiptSHA string `json:"winning_receipt_sha256"`
}
type operatorObservation struct {
	operation      string
	state          string
	code           string
	verified       bool
	floorAbsent    bool
	requestSHA     string
	receiptSHA     string
	version        string
	manifestSHA    string
	manifestSource string
}

func readOperatorObservation(stage string) (operatorObservation, error) {
	var result operatorObservation
	read := func(name string, value any) error {
		path := filepath.Join(stage, name)
		if err := operatorPrivate(path, false); err != nil {
			return err
		}
		info, err := os.Stat(path)
		if err != nil || info.Size() > 4<<20 {
			return errors.New("operator_retention_observation_invalid")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return json.Unmarshal(raw, value)
	}
	var job struct {
		Schema    int    `json:"schema_version"`
		Operation string `json:"operation"`
		Hash      string `json:"request_sha256"`
	}
	var receipt struct {
		State  string `json:"state"`
		Code   string `json:"code"`
		Hash   string `json:"request_sha256"`
		Result struct {
			Verified    bool `json:"verified"`
			FloorAbsent bool `json:"controller_enforcement_floor_absent"`
		} `json:"result"`
	}
	var request struct {
		Variables map[string]any `json:"variables"`
	}
	if err := read("job.json", &job); err != nil {
		return result, err
	}
	if job.Operation != "verify-release" && job.Operation != "verify-bootstrap-automation" && job.Operation != "inspect-upgrade" {
		return result, errors.New("operator_retention_observation_kind_invalid")
	}
	if err := read("receipt.json", &receipt); err != nil {
		return result, err
	}
	if err := read("request.json", &request); err != nil {
		return result, err
	}
	if job.Operation == "inspect-upgrade" {
		var exact map[string]json.RawMessage
		if err := read("request.json", &exact); err != nil {
			return result, err
		}
		lock, lockOK := request.Variables["ultra_lock_directory"].(string)
		var inventory map[string]json.RawMessage
		if operatorPrivate(stage, true) != nil || !strings.HasPrefix(filepath.Base(stage), "controller-preflight-") {
			return result, errors.New("operator_retention_preflight_invalid")
		}
		if len(exact) != 2 || exact["inventory"] == nil || exact["variables"] == nil ||
			json.Unmarshal(exact["inventory"], &inventory) != nil ||
			inventory == nil {
			return result, errors.New("operator_retention_preflight_invalid")
		}
		if len(request.Variables) != 2 || !lockOK || lock == "" ||
			request.Variables["ultra_controller_enforcement_preflight_only"] != true {
			return result, errors.New("operator_retention_preflight_invalid")
		}
	}
	hash, err := sourceSHA(filepath.Join(stage, "request.json"))
	if err != nil || job.Schema != 1 || job.Hash != hash || receipt.Hash != hash {
		return result, errors.New("operator_retention_observation_identity_invalid")
	}
	receiptHash, err := sourceSHA(filepath.Join(stage, "receipt.json"))
	if err != nil {
		return result, err
	}
	result = operatorObservation{
		operation:   job.Operation,
		state:       receipt.State,
		code:        receipt.Code,
		verified:    receipt.Result.Verified,
		floorAbsent: receipt.Result.FloorAbsent,
		requestSHA:  hash,
		receiptSHA:  receiptHash,
	}
	if job.Operation == "verify-release" {
		result.version, _ = request.Variables["ultra_release_version"].(string)
		result.manifestSHA, _ = request.Variables["ultra_release_manifest_sha256"].(string)
	} else {
		result.version, _ = request.Variables["ultra_automation_version"].(string)
		result.manifestSource, _ = request.Variables["ultra_automation_manifest_source"].(string)
	}
	return result, nil
}
func sameOperatorObservationRelease(left, right operatorObservation) bool {
	if left.operation == "inspect-upgrade" {
		return right.operation == left.operation && left.requestSHA == right.requestSHA && right.floorAbsent
	}
	return left.operation == right.operation && left.version != "" && left.version == right.version &&
		left.manifestSHA == right.manifestSHA &&
		left.manifestSource == right.manifestSource
}
func retiredOperatorObservationValid(directory, stage string) bool {
	path := filepath.Join(stage, "observation.retired.json")
	if operatorPrivate(path, false) != nil {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 4096 {
		return false
	}
	var proof retiredOperatorObservation
	if json.Unmarshal(raw, &proof) != nil || proof.Schema != 1 || proof.OperationID != lifecycleID(directory) || proof.Stage != stage ||
		proof.Winner == stage {
		return false
	}
	relative, err := filepath.Rel(directory, proof.Winner)
	if err != nil || filepath.IsAbs(relative) || relative == ".." || len(relative) > 3 && relative[:3] == ".."+string(os.PathSeparator) {
		return false
	}
	original, err := readOperatorObservation(stage)
	if err != nil || original.state != "running" || original.code != "interrupted" || original.requestSHA != proof.RequestSHA ||
		original.receiptSHA != proof.ReceiptSHA {
		return false
	}
	if original.operation == "inspect-upgrade" &&
		(filepath.Dir(stage) != directory || filepath.Dir(proof.Winner) != directory || operatorPrivate(directory, true) != nil) {
		return false
	}
	winner, err := readOperatorObservation(proof.Winner)
	return err == nil && winner.state == "succeeded" && winner.verified && winner.requestSHA == proof.WinnerRequestSHA &&
		winner.receiptSHA == proof.WinnerReceiptSHA &&
		sameOperatorObservationRelease(original, winner)
}

// controller.py writes interrupted only after killing and waiting for the entire
// child process group. A later successful same-release observation supersedes
// that cancelled check. Controller preflight additionally requires the exact
// same inventory and lock request, with an explicit absent-floor acknowledgement.
// Mutators and unauthenticated running jobs are never retired.
func retireInterruptedOperatorObservations(directory, kind string, manifest *automationRelease, manifestSHA string) error {
	expectedOperation := "verify-release"
	if kind == "bootstrap" {
		expectedOperation = "verify-bootstrap-automation"
	}
	observations := map[string]operatorObservation{}
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() &&
			(entry.Name() == "bundle" || entry.Name() == "recovery-bundle" || entry.Name() == "ansible-tmp" || entry.Name() == "__pycache__") {
			return filepath.SkipDir
		}
		if entry.Name() != "job.json" {
			return nil
		}
		observation, err := readOperatorObservation(filepath.Dir(path))
		if err != nil {
			return nil
		}
		if observation.operation != expectedOperation || observation.version != manifest.Version {
			if kind != "upgrade" || observation.operation != "inspect-upgrade" || filepath.Dir(filepath.Dir(path)) != directory ||
				operatorPrivate(directory, true) != nil {
				return nil
			}
		}
		if observation.operation == "verify-release" && observation.manifestSHA != manifestSHA {
			return nil
		}
		if observation.operation == "verify-bootstrap-automation" {
			hash, err := sourceSHA(observation.manifestSource)
			if err != nil || hash != manifestSHA {
				return nil
			}
		}
		observations[filepath.Dir(path)] = observation
		return nil
	})
	if err != nil {
		return err
	}
	for stage, original := range observations {
		if original.state != "running" || original.code != "interrupted" {
			continue
		}
		if retiredOperatorObservationValid(directory, stage) {
			continue
		}
		for winnerStage, winner := range observations {
			if winner.state != "succeeded" || !winner.verified || !sameOperatorObservationRelease(original, winner) {
				continue
			}
			proof := retiredOperatorObservation{
				1,
				lifecycleID(directory),
				stage,
				original.requestSHA,
				original.receiptSHA,
				winnerStage,
				winner.requestSHA,
				winner.receiptSHA,
			}
			raw, _ := json.Marshal(proof)
			if err := writeUpgradeInput(filepath.Join(stage, "observation.retired.json"), raw); err != nil {
				return err
			}
			break
		}
	}
	return nil
}
