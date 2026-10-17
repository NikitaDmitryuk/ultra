package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestUpgradeAcceptedResumeBindsExactGenerationAndDomainAttempt(t *testing.T) {
	directory := t.TempDir()
	p := &installplan.InstallPlan{SourceValues: map[string]string{}, Bot: installplan.BotConfig{Enabled: false}}
	inventory := map[string]any{"all": map[string]any{"children": map[string]any{"exits": map[string]any{"hosts": map[string]any{}}}}}
	binding := strings.Repeat("a", 64)
	domain := &upgradeDomainTransaction{
		Changed:        true,
		BackendChanged: true,
		Binding:        binding,
		Variables: map[string]any{
			"ultra_ingress":            map[string]any{"domain": "edge.example.com"},
			"ultra_backend_old_domain": "old.example.com",
			"ultra_bot_domain":         "bot.example.com",
			"ultra_backend_old_public": "sync.example.com",
			"ultra_backend_old_port":   8444,
			"ultra_bot_port":           8445,
		},
	}
	contract, err := upgradeAcceptedResumeContract(
		p,
		upgradeInspection{},
		inventory,
		map[string]any{"ultra_upgrade_domain_binding": binding},
		directory,
		domain,
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	var in runtimeProbeInput
	if json.Unmarshal([]byte(contract["runtime_request_json"].(string)), &in) != nil ||
		in.Request.Transaction != fmt.Sprintf("%s-runtime-2", lifecycleID(directory)) ||
		in.DomainTransaction != binding ||
		in.Request.BotEnabled {
		t.Fatalf("candidate request lost desired settings: %+v", in)
	}
	d := contract["domain"].(map[string]any)
	if contract["generation"] != 2 || d["attempt"] != 1 || d["binding"] != binding ||
		d["backend_policy"].(map[string]any)["new_port"] != 8445 {
		t.Fatal("resume did not bind domain generation, attempt and backend policy")
	}
	// Committed continuation previously passed nil to resume, selecting
	// restore-services against an already accepted candidate configuration.
	retry, accepted := upgradeRetryResumeContracts(contract, true)
	if retry["mode"] != "committed" || accepted == nil || !reflect.DeepEqual(accepted, contract) {
		t.Fatal("committed retry lost exact accepted runtime/domain evidence")
	}
	retry["target_sha256"], retry["release_version"] = strings.Repeat("b", 64), "v1.0.0"
	if len(accepted) != 3 || accepted["mode"] != nil || accepted["target_sha256"] != nil || accepted["release_version"] != nil ||
		accepted["runtime_request_json"] != contract["runtime_request_json"] || !reflect.DeepEqual(accepted["domain"], d) {
		t.Fatal("retry-only metadata contaminated accepted resume contract")
	}
	failedRetry, failedAccepted := upgradeRetryResumeContracts(contract, false)
	if failedRetry["mode"] != "compensation" || failedAccepted != nil {
		t.Fatal("uncommitted retry received accepted resume authority")
	}
}

func TestUpgradeCommittedResumeRequiresExactSuccessfulEvidence(t *testing.T) {
	for _, drift := range []string{"none", "operation", "request", "job-hash", "job-binary", "receipt-hash", "receipt-binary", "state", "accepted-contract"} {
		t.Run(drift, func(t *testing.T) {
			directory := t.TempDir()
			inventory := map[string]any{"all": map[string]any{"derived": 2}}
			accepted := map[string]any{"generation": 1, "runtime_request_json": "frozen-runtime-request"}
			variables := upgradeResumeVariables("/private/lock", lifecycleID(directory), true, strings.Repeat("a", 64), accepted)
			if complete, err := successfulUpgradeResume(directory, inventory, variables); err != nil || complete {
				t.Fatal("missing resume considered complete", err)
			}
			stage := filepath.Join(directory, "resume-success")
			if err := os.Mkdir(stage, 0700); err != nil {
				t.Fatal(err)
			}
			retentionWriteJSON(t, stage, "request.json", map[string]any{"inventory": inventory, "variables": variables})
			hash, _ := sourceSHA(filepath.Join(stage, "request.json"))
			binary := strings.Repeat("b", 64)
			retentionWriteJSON(
				t,
				stage,
				"job.json",
				map[string]any{"schema_version": 1, "operation": "resume-automation", "request_sha256": hash, "binary_sha256": binary},
			)
			retentionWriteJSON(
				t,
				stage,
				"receipt.json",
				map[string]any{"state": "succeeded", "request_sha256": hash, "binary_sha256": binary},
			)
			switch drift {
			case "operation":
				retentionMutateJSON(t, stage, "job.json", func(v map[string]any) { v["operation"] = "upgrade" })
			case "request":
				retentionMutateJSON(t, stage, "request.json", func(v map[string]any) { v["inventory"] = map[string]any{"changed": true} })
			case "job-hash":
				retentionMutateJSON(t, stage, "job.json", func(v map[string]any) { v["request_sha256"] = strings.Repeat("0", 64) })
			case "job-binary":
				retentionMutateJSON(t, stage, "job.json", func(v map[string]any) { v["binary_sha256"] = "invalid" })
			case "receipt-hash":
				retentionMutateJSON(t, stage, "receipt.json", func(v map[string]any) { v["request_sha256"] = strings.Repeat("0", 64) })
			case "receipt-binary":
				retentionMutateJSON(t, stage, "receipt.json", func(v map[string]any) { v["binary_sha256"] = strings.Repeat("c", 64) })
			case "state":
				retentionMutateJSON(t, stage, "receipt.json", func(v map[string]any) { v["state"] = "failed" })
			case "accepted-contract":
				accepted["generation"] = 2
			}
			complete, err := successfulUpgradeResume(directory, inventory, variables)
			if err != nil || complete != (drift == "none") {
				t.Fatal("incorrect resume reuse", complete, err)
			}
		})
	}
}
