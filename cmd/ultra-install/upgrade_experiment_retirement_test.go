package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

func TestUpgradeExperimentalRetirementUsesCurrentLeaseAndStableJob(t *testing.T) {
	type leaseKey struct{}
	ctx := context.WithValue(context.Background(), leaseKey{}, "held")
	inventory := map[string]any{"bridge": "frozen"}
	variables := map[string]any{"ultra_lock_directory": "/private/held-lock", "ultra_ingress": "desired-not-observed"}
	directory := t.TempDir()
	calls := 0
	run := func(received context.Context, operation string, hosts, request map[string]any, stage, python, executable string) (deployansible.Receipt, error) {
		calls++
		if received.Value(leaseKey{}) != "held" || operation != "ingress" || !reflect.DeepEqual(hosts, inventory) ||
			stage != filepath.Join(directory, "retire-experiment") || python != "python" || executable != "ansible" {
			t.Fatal("retirement lost current execution/lease binding")
		}
		if !reflect.DeepEqual(request, map[string]any{"ultra_lock_directory": "/private/held-lock", "ultra_ingress_action": "retire-experiment"}) {
			t.Fatal("retirement used desired endpoint metadata", request)
		}
		return deployansible.Receipt{}, nil
	}
	for range 2 {
		if err := applyUpgradeExperimentalRetirement(ctx, inventory, variables, directory, "python", "ansible", run); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 || variables["ultra_ingress"] != "desired-not-observed" {
		t.Fatal("request is not repeatable or changed caller inputs")
	}
}

func TestUpgradeExperimentalRetirementPropagatesProofFailure(t *testing.T) {
	proof := errors.New("cache proof unavailable")
	err := applyUpgradeExperimentalRetirement(context.Background(), nil, nil, t.TempDir(), "", "",
		func(context.Context, string, map[string]any, map[string]any, string, string, string) (deployansible.Receipt, error) {
			return deployansible.Receipt{}, proof
		})
	if !errors.Is(err, proof) || !strings.Contains(err.Error(), "upgrade_experimental_retirement_incomplete") {
		t.Fatal("upgrade accepted failed retirement", err)
	}
}

func TestUpgradeExperimentalRetirementPrecedesRuntimeAndBinaryMutation(t *testing.T) {
	raw, err := os.ReadFile("ansible_upgrade.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	start := strings.Index(source, "domainTransaction, err = inspectUpgradeDomains(")
	retire := strings.Index(source, "if err = runUpgradeExperimentalRetirement(")
	runtime := strings.Index(source, "if err = inspectUpgradeRuntimeForPurpose(")
	activation := strings.Index(source, "activation, activationErr := deployansible.RunLocal(")
	if start < 0 || retire <= start || runtime <= retire || activation <= runtime ||
		!strings.Contains(source[retire:runtime], "return err") {
		t.Fatal("runtime activation can occur before retirement proof")
	}
}
