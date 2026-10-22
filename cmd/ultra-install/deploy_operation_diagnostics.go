package main

// Only fixed classifications may leave protected diagnostics. Never persist
// arbitrary error text, which can include addresses, paths or credentials.
var deployOperationNextActions = map[string]string{
	"execution_containment_unavailable":                         "restore_systemd_execution_prerequisites",
	"execution_containment_unverified":                          "inspect_systemd_execution_owner",
	"execution_containment_stop_unverified":                     "inspect_and_reconcile_exact_execution",
	"deploy_post_activation_execution_uncertain":                "inspect_and_reconcile_exact_execution",
	"deploy_post_activation_reconcile_uncertain":                "inspect_and_reconcile_exact_execution",
	"deploy_post_activation_infrastructure_lease_held":          "inspect_infrastructure_operation",
	"deploy_post_activation_candidate_manifest_required":        "inspect_application_baseline",
	"deploy_post_activation_candidate_changed":                  "restore_verified_candidate",
	"deploy_post_activation_plan_changed":                       "restore_verified_inputs",
	"recovery_post_activation_schedule_checkpoint_required":     "inspect_recovery_schedule_restoration",
	"recovery_post_activation_reconcile_uncertain":              "inspect_and_reconcile_exact_execution",
	"recovery_post_activation_execution_uncertain":              "inspect_and_reconcile_exact_execution",
	"recovery_post_activation_infrastructure_lease_held":        "inspect_infrastructure_operation",
	"recovery_post_activation_candidate_manifest_required":      "inspect_application_baseline",
	"recovery_preparation_original_baseline_incomplete":         "restore_verified_original_release",
	"recovery_preparation_original_installers_missing":          "restore_verified_original_release",
	"recovery_preparation_application_baseline_changed":         "inspect_application_baseline",
	"recovery_preparation_primary_identity_changed":             "inspect_primary_identity",
	"recovery_preparation_primary_or_queue_changed":             "inspect_primary_and_operation_queue",
	"recovery_preparation_fresh_independent_readiness_required": "verify_independent_backup_and_readiness",
	"recovery_preparation_readiness_reasons_nonempty":           "inspect_readiness_reasons",
	"recovery_preparation_dispatch_uncertain":                   "inspect_and_reconcile_exact_execution",
	"recovery_preparation_reconcile_uncertain":                  "inspect_and_reconcile_exact_execution",
	"recovery_preparation_execution_fence_unresolved":           "inspect_and_reconcile_exact_execution",
	"recovery_preparation_ansible_completion_unproven":          "inspect_and_reconcile_exact_execution",
	"recovery_preparation_candidate_runtime_changed":            "restore_verified_candidate",
	"recovery_preparation_inputs_changed":                       "restore_verified_inputs",
	"recovery_preparation_accepted_pins_changed":                "inspect_pinned_server_identities",
	"recovery_preparation_monitor_proof_missing":                "inspect_recovery_monitor_initialization",
}

func deployOperationFailureReason(phase string, err error) string {
	// Bound arbitrary/custom unwrap implementations and joined error trees.
	pending := []error{err}
	for visited := 0; len(pending) != 0 && visited < 32; visited++ {
		current := pending[0]
		pending = pending[1:]
		if current == nil {
			continue
		}
		if _, ok := deployOperationNextActions[current.Error()]; ok {
			return current.Error()
		}
		switch wrapped := current.(type) {
		case interface{ Unwrap() []error }:
			children := wrapped.Unwrap()
			if len(children) > 32-len(pending) {
				children = children[:32-len(pending)]
			}
			pending = append(pending, children...)
		case interface{ Unwrap() error }:
			pending = append(pending, wrapped.Unwrap())
		}
	}
	return "deploy_operation_" + phase + "_failed"
}

type deployOperationObservation struct {
	deployOperationState
	NextAction string `json:"next_action,omitempty"`
}

func observeDeployOperation(state deployOperationState) deployOperationObservation {
	next := ""
	if state.State == "blocked" {
		next = deployOperationNextActions[state.Reason]
		if next == "" {
			next = "inspect_protected_diagnostics_and_reconcile"
		}
	}
	return deployOperationObservation{state, next}
}
