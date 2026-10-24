package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func checkReplacementQuiescence(ctx context.Context, p *installplan.InstallPlan, target replacementTarget, primary bool) error {
	raw, err := retainedRemote(
		ctx,
		p,
		target.Address,
		target.Identity,
		primary,
		replacementQuiescenceProgram,
		[]string{target.Role, p.Database.Name},
	)
	if err != nil {
		return fmt.Errorf("replacement_quiescence_probe_unavailable: %w", err)
	}
	return replacementQuiescenceResult(raw)
}

func replacementQuiescenceResult(raw []byte) error {
	var result struct {
		Quiescent bool   `json:"quiescent"`
		Code      string `json:"code"`
		Offender  *struct {
			PID           int      `json:"pid"`
			PPID          int      `json:"ppid"`
			SID           int      `json:"sid"`
			Comm          string   `json:"comm"`
			ArgvBasenames []string `json:"argv_basenames"`
			Cgroups       []string `json:"cgroups"`
		} `json:"offender"`
	}
	if retainedReconcileUniqueJSON(raw) != nil || json.Unmarshal(raw, &result) != nil {
		return errors.New("replacement_quiescence_result_invalid")
	}
	if !result.Quiescent {
		switch result.Code {
		case "replacement_other_root_ssh_session",
			"replacement_unknown_root_helper",
			"replacement_session_census_unavailable",
			"replacement_helper_session_unisolated",
			"replacement_tunnel_uid_unavailable",
			"replacement_primary_client_transactions_active",
			"replacement_primary_activity_unavailable":
			if result.Offender != nil {
				detail, _ := json.Marshal(result.Offender)
				return fmt.Errorf("%s: offender=%s", result.Code, detail)
			}
			return errors.New(result.Code)
		default:
			return errors.New("replacement_quiescence_not_verified")
		}
	}
	return nil
}
