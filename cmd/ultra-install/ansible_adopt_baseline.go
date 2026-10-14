package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// This exact unit shipped before the provider-pool startup flag was added.
// Accepting its hash permits an explicit upgrade; arbitrary observed units do
// not become an accepted baseline merely because an SSH inspection read them.
const legacyRelayUnitSHA = "c5d05f7fd4be75d65061f4a04df4b1936059601c4aa3349659b81d075dc60cee"

func prepareAdoptionBaseline(p *installplan.InstallPlan, inventory map[string]any, inspection map[string]bootstrapInspection) error {
	if !p.AdoptRuntime {
		return nil
	}
	raw, err := inspection["bridge"].file("release-manifest.json")
	if err != nil || len(raw) == 0 || len(raw) > 1024*1024 {
		return fmt.Errorf("adoption_installed_release_manifest_required")
	}
	var manifest map[string]any
	if json.Unmarshal(raw, &manifest) != nil {
		return fmt.Errorf("adoption_installed_release_manifest_invalid")
	}
	version, _ := manifest["version"].(string)
	if !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(version) {
		return fmt.Errorf("adoption_installed_release_manifest_invalid")
	}
	caps, _ := manifest["capabilities"].([]any)
	required := map[string]bool{"service-access-v1": false, "provider-pool-quota-v1": false}
	for _, cap := range caps {
		if name, ok := cap.(string); ok {
			if _, needed := required[name]; needed {
				required[name] = true
			}
		}
	}
	for _, present := range required {
		if !present {
			return fmt.Errorf("adoption_installed_accounting_contract_required")
		}
	}
	assets, ok := manifest["assets"].([]any)
	if !ok || len(assets) == 0 {
		return fmt.Errorf("adoption_installed_release_manifest_invalid")
	}
	vars := inventory["all"].(map[string]any)["vars"].(map[string]any)
	vars["ultra_adoption_installed_manifest"] = manifest
	vars["ultra_adoption_topology_sha256"] = inspection["bridge"].TopologySHA
	vars["ultra_adoption_database"] = p.Database.Name
	vars["ultra_previous_relay_unit_sha256"] = legacyRelayUnitSHA
	return nil
}

// Inventory uses the original JSON maps so omitempty cannot turn explicit []
// into nil/default routing rules when serializing the frozen Ansible request.
func preserveAdoptionJSON(p *installplan.InstallPlan, desired *installplan.DesiredState, inventory map[string]any) error {
	if !p.AdoptRuntime {
		return nil
	}
	children := inventory["all"].(map[string]any)["children"].(map[string]any)
	decode := func(raw []byte) (map[string]any, error) {
		var object map[string]any
		if len(raw) == 0 || json.Unmarshal(raw, &object) != nil || object == nil {
			return nil, fmt.Errorf("adoption_specification_json_required")
		}
		return object, nil
	}
	bridge, err := decode(desired.BridgeSpec)
	if err != nil {
		return err
	}
	children["bridge"].(map[string]any)["hosts"].(map[string]any)["bridge"].(map[string]any)["ultra_spec"] = bridge
	nodes := children["exits"].(map[string]any)["hosts"].(map[string]any)
	for i, exit := range p.Exits {
		object, err := decode(desired.ExitSpecs[exit.Name])
		if err != nil {
			return err
		}
		nodes["exit_"+strconv.Itoa(i)].(map[string]any)["ultra_spec"] = object
	}
	return nil
}
