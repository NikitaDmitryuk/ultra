package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestUpgradeApplyingReservationPurposeAndOrdering(t *testing.T) {
	for _, reserveFirst := range []bool{false, true} {
		for _, corruption := range []string{"", "receipt", "bridge", "alias", "group-vars", "common", "exit-auth"} {
			t.Run(
				map[bool]string{false: "drain-first", true: "reserve-first"}[reserveFirst]+"/"+corruption,
				func(t *testing.T) {
					directory := t.TempDir()
					if err := os.Chmod(directory, 0700); err != nil {
						t.Fatal(err)
					}
					local := false
					p := &installplan.InstallPlan{ControllerLocal: &local}
					inventory := map[string]any{"all": map[string]any{
						"vars": map[string]any{"ansible_ssh_private_key_file": "/fixture/identity"},
						"children": map[string]any{
							"bridge": map[string]any{
								"hosts": map[string]any{
									"bridge": map[string]any{"ansible_host": "192.0.2.1"},
								},
							},
							"exits": map[string]any{"hosts": map[string]any{}},
						},
					}}
					for _, reserve := range []bool{false, true} {
						name := "lifecycle-applying-a"
						if reserve != reserveFirst {
							name = "lifecycle-applying-z"
						}
						stage := filepath.Join(directory, name)
						if err := os.Mkdir(stage, 0700); err != nil {
							t.Fatal(err)
						}
						vars := map[string]any{
							"ultra_lifecycle_id":           lifecycleID(directory),
							"ultra_lifecycle_phase":        "applying",
							"ultra_lifecycle_drain":        !reserve,
							"ultra_lifecycle_reserve_only": reserve,
						}
						stageInventory := inventory
						if !reserve {
							// Drain's inventory already includes discovered exits and baseline manifests.
							raw, _ := json.Marshal(inventory)
							stageInventory = nil
							if err := json.Unmarshal(raw, &stageInventory); err != nil {
								t.Fatal(err)
							}
							children := stageInventory["all"].(map[string]any)["children"].(map[string]any)
							alias := "exit_11111111222233334444555555555555"
							hosts := map[string]any{alias: map[string]any{
								"ansible_host": "192.0.2.2", "ansible_user": "root",
								"ansible_ssh_private_key_file": filepath.Join(
									directory,
									"identity",
								),
								"ansible_ssh_args": "-F /dev/null -o ControlMaster=no -o ControlPath=none",
								"ansible_ssh_common_args": "-o BatchMode=yes -o UpdateHostKeys=no -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -o UserKnownHostsFile=" + shellQuote(
									filepath.Join(directory, alias+".pins"),
								),
								"ultra_exit_id":                "11111111-2222-3333-4444-555555555555",
								"ultra_host_previous_manifest": map[string]any{"version": "v1.0.0"},
							}}
							children["exits"] = map[string]any{"hosts": hosts}
							switch corruption {
							case "bridge":
								children["bridge"].(map[string]any)["hosts"].(map[string]any)["bridge"].(map[string]any)["ansible_host"] = "192.0.2.99"
							case "alias":
								hosts["bridge"] = map[string]any{"ansible_host": "192.0.2.99"}
							case "group-vars":
								children["exits"].(map[string]any)["vars"] = map[string]any{
									"ansible_host": "192.0.2.99",
								}
							case "exit-auth":
								hosts[alias].(map[string]any)["ansible_ssh_private_key_file"] = "/foreign/identity"
							case "common":
								stageInventory["all"].(map[string]any)["vars"].(map[string]any)["ansible_ssh_private_key_file"] = "/foreign/identity"
							}
						}
						request, _ := json.Marshal(
							map[string]any{"inventory": stageInventory, "variables": vars},
						)
						hash := digestSHA256(request)
						job := map[string]any{
							"schema_version": 1,
							"operation":      "lifecycle",
							"request_sha256": hash,
							"binary_sha256":  hash,
						}
						result := map[string]any{"verified": true}
						if reserve {
							result["reservation_id"] = lifecycleID(directory)
							result["reservation_phase"] = "applying"
						}
						receipt := map[string]any{
							"schema_version": 1,
							"operation":      "lifecycle",
							"request_sha256": hash,
							"binary_sha256":  hash,
							"state":          "succeeded",
							"result":         result,
						}
						if corruption == "receipt" && !reserve {
							receipt["request_sha256"] = "changed"
						}
						for name, value := range map[string]any{"request.json": json.RawMessage(request), "job.json": job, "receipt.json": receipt} {
							raw, err := json.Marshal(value)
							if err != nil {
								t.Fatal(err)
							}
							if err := os.WriteFile(filepath.Join(stage, name), raw, 0600); err != nil {
								t.Fatal(err)
							}
						}
					}
					reserved, err := upgradeHasApplyingReservation(
						p,
						directory,
						directory,
						inventory,
					)
					if corruption != "" {
						if err == nil {
							t.Fatal("tampered drain receipt accepted")
						}
					} else if err != nil || !reserved {
						t.Fatalf("reservation=%t err=%v", reserved, err)
					}
				},
			)
		}
	}
}

func TestUpgradeApplyingReservationPending(t *testing.T) {
	directory := t.TempDir()
	stage := filepath.Join(directory, "lifecycle-applying-interrupted")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	if upgradeApplyingReservationPending(directory) {
		t.Fatal("unsubmitted stage is not pending")
	}
	if err := os.WriteFile(filepath.Join(stage, "job.json"), []byte(`{"state":"running"}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, receipt := range []string{"", `{"state":"running"}`, `{"state":"failed"}`} {
		if receipt != "" {
			if err := os.WriteFile(filepath.Join(stage, "receipt.json"), []byte(receipt), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if !upgradeApplyingReservationPending(directory) {
			t.Fatalf("interrupted stage not pending: %s", receipt)
		}
	}
}
