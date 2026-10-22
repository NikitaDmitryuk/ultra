package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

func TestDeployOperationPreservesSafeReasonWithoutRetryPrivilege(t *testing.T) {
	for _, reason := range []string{"recovery_preparation_original_baseline_incomplete", "recovery_preparation_fresh_independent_readiness_required"} {
		t.Run(reason, func(t *testing.T) {
			directory, request := deployPreparationFixture(t, "tools_staged", "prepared")
			calls := 0
			prepare := func(context.Context, string, recoveryPreparationRequest, []string) error {
				calls++
				return fmt.Errorf("private diagnostic: %w", errors.New(reason))
			}
			observe := func(context.Context, string, recoveryPreparationRequest, []string) error {
				return errors.New("no exact terminal proof")
			}
			run := func(context.Context, []string) error { t.Fatal("upgrade dispatched"); return nil }
			if err := runDeployOperationPhases(context.Background(), directory, request, run, prepare, observe); err == nil ||
				err.Error() != reason {
				t.Fatalf("lost safe classification: %v", err)
			}
			state, err := readDeployOperation(directory, request)
			if err != nil || state.State != "blocked" || observeDeployOperation(state).NextAction != deployOperationNextActions[reason] {
				t.Fatalf("missing diagnostic: %+v %v", state, err)
			}
			if err = runDeployOperationPhases(context.Background(), directory, request, run, prepare, observe); err == nil || calls != 1 {
				t.Fatal("diagnostic enabled retry without proof")
			}
			state.Reason = "secret or infrastructure value"
			if err = saveDeployOperation(filepath.Join(directory, "state.json"), state); err != nil {
				t.Fatal(err)
			}
			if _, err = readDeployOperation(directory, request); err == nil {
				t.Fatal("arbitrary reason accepted")
			}
		})
	}
}

func TestDeployOperationFailureReasonNeverCopiesPrivateText(t *testing.T) {
	err := errors.New("recovery_preparation_original_baseline_incomplete at private path")
	if got := deployOperationFailureReason("tools_staged", err); got != "deploy_operation_tools_staged_failed" {
		t.Fatal(got)
	}
	joined := errors.Join(errors.New("private"), errors.New("recovery_preparation_primary_identity_changed"))
	if got := deployOperationFailureReason("tools_staged", joined); got != "recovery_preparation_primary_identity_changed" {
		t.Fatal(got)
	}
}
