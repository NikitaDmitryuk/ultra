package main

import (
	"crypto/subtle"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// prepareProviderSecrets creates disposable projections, never additional operator inputs.
func prepareProviderSecrets(p *installplan.InstallPlan, directory string) (string, string, error) {
	if p == nil || p.Automation == nil {
		return "", "", errors.New("automation configuration required")
	}
	values, err := readProviderSecretValues(p)
	if err != nil {
		return "", "", err
	}
	compute := p.Automation.CloudKeyFile
	if values["ULTRA_VULTR_API_KEY"] != "" {
		compute, err = writeProviderSecret(directory, "compute-key", values["ULTRA_VULTR_API_KEY"])
		if err != nil {
			return "", "", err
		}
	}
	dns := ""
	if p.Automation.DNS != nil {
		dns, err = writeProviderSecret(directory, "dns-key", values["ULTRA_VULTR_DNS_API_KEY"])
		if err != nil {
			return "", "", err
		}
		if dns == "" {
			return "", "", errors.New("ULTRA_VULTR_DNS_API_KEY missing from canonical secrets")
		}
	}
	return compute, dns, nil
}

func prepareComputeProviderSecret(p *installplan.InstallPlan, directory string) (string, error) {
	if p == nil || p.Automation == nil {
		return "", errors.New("automation configuration required")
	}
	values, err := readProviderSecretValues(p)
	if err != nil {
		return "", err
	}
	compute := p.Automation.CloudKeyFile
	if strings.TrimSpace(values["ULTRA_VULTR_API_KEY"]) == "" {
		return compute, nil
	}
	return writeProviderSecret(directory, "compute-key", values["ULTRA_VULTR_API_KEY"])
}

func readProviderSecretValues(p *installplan.InstallPlan) (map[string]string, error) {
	values, err := installplan.ReadSecretsFile(p.SecretsEnvFile())
	if err != nil && !os.IsNotExist(err) {
		return nil, errors.New("canonical secrets unavailable")
	}
	return values, nil
}

func writeProviderSecret(directory, name, raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("invalid provider credential")
	}
	file := filepath.Join(directory, name)
	if info, statErr := os.Lstat(file); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return "", errors.New("invalid staged provider credential")
		}
		staged, readErr := os.ReadFile(file)
		if readErr != nil || len(staged) != len(value) || subtle.ConstantTimeCompare(staged, []byte(value)) != 1 {
			return "", errors.New("provider credential changed during operation")
		}
		return file, nil
	} else if !os.IsNotExist(statErr) {
		return "", statErr
	}
	if err := os.WriteFile(file, []byte(value), 0600); err != nil {
		return "", err
	}
	return file, nil
}
