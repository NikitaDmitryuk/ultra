package main

import (
	"encoding/json"
	"errors"
)

// expectedFrozenLocalRequest reconstructs the entire admitted wire request.
// Historical requests may omit the execution budget; newer receipts must retain
// its exact positive value in the bytes authenticated by job/receipt hashes.
// No fields are discarded and duplicate keys/unknown fields are rejected.
func expectedFrozenLocalRequest(raw []byte, inventory, variables map[string]any) ([]byte, error) {
	var submitted struct {
		Inventory json.RawMessage `json:"inventory"`
		Variables json.RawMessage `json:"variables"`
		Seconds   *int64          `json:"execution_timeout_seconds,omitempty"`
	}
	if decodeRetainedReconcile(raw, &submitted) != nil || len(submitted.Inventory) == 0 || len(submitted.Variables) == 0 {
		return nil, errors.New("frozen_local_request_invalid")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil, errors.New("frozen_local_request_invalid")
	}
	if _, present := fields["execution_timeout_seconds"]; present && submitted.Seconds == nil {
		return nil, errors.New("invalid_execution_timeout")
	}
	expected := map[string]any{"inventory": inventory, "variables": variables}
	if submitted.Seconds != nil {
		if *submitted.Seconds <= 0 || *submitted.Seconds > 9223371976 {
			return nil, errors.New("invalid_execution_timeout")
		}
		expected["execution_timeout_seconds"] = *submitted.Seconds
	}
	return json.Marshal(expected)
}
