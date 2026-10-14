package main

import (
	"encoding/base64"
	"encoding/json"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
	"testing"
)

func TestPrepareAdoptionInstalledBaseline(t *testing.T) {
	valid := `{"version":"v2.4.6","capabilities":["service-access-v1","provider-pool-quota-v1"],"assets":[{"name":"ultra-relay-linux-amd64","sha256":"fixture"}]}`
	for _, tc := range []struct {
		name, raw string
		wantErr   bool
	}{
		{"current release", valid, false}, {"missing manifest", "", true}, {"malformed manifest", "{", true},
		{"missing accounting contract", `{"version":"v2.4.6","capabilities":[],"assets":[{}]}`, true},
		{"invalid version", `{"version":"latest","capabilities":["service-access-v1","provider-pool-quota-v1"],"assets":[{}]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var inspection bootstrapInspection
			encoded, _ := json.Marshal(map[string]any{"files": []map[string]string{{"source": "/opt/ultra-recovery/release-manifest.json", "content": base64.StdEncoding.EncodeToString([]byte(tc.raw))}}})
			if err := json.Unmarshal(encoded, &inspection); err != nil {
				t.Fatal(err)
			}
			vars := map[string]any{}
			inventory := map[string]any{"all": map[string]any{"vars": vars}}
			err := prepareAdoptionBaseline(&installplan.InstallPlan{AdoptRuntime: true}, inventory, map[string]bootstrapInspection{"bridge": inspection})
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v wantErr=%v", err, tc.wantErr)
			}
			if !tc.wantErr && (vars["ultra_previous_relay_unit_sha256"] != legacyRelayUnitSHA || vars["ultra_adoption_installed_manifest"] == nil) {
				t.Fatal("trusted installed baseline missing")
			}
		})
	}
	if err := prepareAdoptionBaseline(&installplan.InstallPlan{}, nil, nil); err != nil {
		t.Fatal("ordinary installation unexpectedly requires previous manifest")
	}
}

func TestAdoptionInventoryPreservesExplicitEmptyRouting(t *testing.T) {
	p := &installplan.InstallPlan{AdoptRuntime: true, Exits: []installplan.ExitNode{{Name: "exit"}}}
	bridge := map[string]any{}
	exit := map[string]any{}
	inventory := map[string]any{"all": map[string]any{"children": map[string]any{
		"bridge": map[string]any{"hosts": map[string]any{"bridge": bridge}},
		"exits":  map[string]any{"hosts": map[string]any{"exit_0": exit}},
	}}}
	ds := &installplan.DesiredState{BridgeSpec: []byte(`{"geoip_direct_tags":[],"future_setting":{"enabled":false}}`), ExitSpecs: map[string][]byte{"exit": []byte(`{"geosite_direct_tags":[]}`)}}
	if err := preserveAdoptionJSON(p, ds, inventory); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]any
	if err = json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	children := saved["all"].(map[string]any)["children"].(map[string]any)
	bridge = children["bridge"].(map[string]any)["hosts"].(map[string]any)["bridge"].(map[string]any)
	exit = children["exits"].(map[string]any)["hosts"].(map[string]any)["exit_0"].(map[string]any)
	tags, ok := bridge["ultra_spec"].(map[string]any)["geoip_direct_tags"].([]any)
	if !ok || tags == nil || len(tags) != 0 {
		t.Fatal("inventory changed explicit [] to default routing")
	}
	if _, ok := exit["ultra_spec"].(map[string]any)["geosite_direct_tags"].([]any); !ok {
		t.Fatal("exit empty array missing")
	}
	if bridge["ultra_spec"].(map[string]any)["future_setting"] == nil {
		t.Fatal("unknown original field lost")
	}
	if err := preserveAdoptionJSON(&installplan.InstallPlan{}, nil, nil); err != nil {
		t.Fatal("normal installation changed")
	}
}
