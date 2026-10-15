package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestUpgradeAcceptedResumeBindsExactGenerationAndDomainAttempt(t *testing.T) {
	directory := t.TempDir()
	p := &installplan.InstallPlan{SourceValues: map[string]string{}, Bot: installplan.BotConfig{Enabled: false}}
	inventory := map[string]any{"all": map[string]any{"children": map[string]any{"exits": map[string]any{"hosts": map[string]any{}}}}}
	binding := strings.Repeat("a", 64)
	domain := &upgradeDomainTransaction{Changed: true, BackendChanged: true, Binding: binding, Variables: map[string]any{"ultra_ingress": map[string]any{"domain": "edge.example.com"}, "ultra_backend_old_domain": "old.example.com", "ultra_bot_domain": "bot.example.com", "ultra_backend_old_public": "sync.example.com", "ultra_backend_old_port": 8444, "ultra_bot_port": 8445}}
	contract, err := upgradeAcceptedResumeContract(p, upgradeInspection{}, inventory, map[string]any{"ultra_upgrade_domain_binding": binding}, directory, domain, 2)
	if err != nil {
		t.Fatal(err)
	}
	var in runtimeProbeInput
	if json.Unmarshal([]byte(contract["runtime_request_json"].(string)), &in) != nil || in.Request.Transaction != fmt.Sprintf("%s-runtime-2", lifecycleID(directory)) || in.DomainTransaction != binding || in.Request.BotEnabled {
		t.Fatalf("candidate request lost desired settings: %+v", in)
	}
	d := contract["domain"].(map[string]any)
	if contract["generation"] != 2 || d["attempt"] != 1 || d["binding"] != binding || d["backend_policy"].(map[string]any)["new_port"] != 8445 {
		t.Fatal("resume did not bind domain generation, attempt and backend policy")
	}
}
