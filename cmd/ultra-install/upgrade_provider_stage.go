package main

import (
	"os"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func prepareUpgradeProviderStage(p *installplan.InstallPlan, directory string, generation int) (string, string, func() error, error) {
	if p == nil || p.Automation == nil || generation < 1 {
		return "", "", nil, nil
	}
	stage := upgradeDependentStageDirectory(directory, "provider-secrets", generation)
	if err := ensurePrivateBootstrapDirectory(stage); err != nil {
		return "", "", nil, err
	}
	compute, err := prepareComputeProviderSecret(p, stage)
	if err != nil {
		return "", "", nil, err
	}
	if compute == "" {
		_ = os.RemoveAll(stage)
		return "", "", nil, nil
	}
	cleanup := func() error { return os.RemoveAll(stage) }
	return compute, p.Bridge.Address, cleanup, nil
}
