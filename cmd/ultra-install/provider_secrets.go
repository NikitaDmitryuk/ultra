package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// prepareProviderSecrets creates disposable projections, never additional operator inputs.
func prepareProviderSecrets(p *installplan.InstallPlan, directory string) (string, string, error) {
	values, err := installplan.ReadSecretsFile(p.SecretsEnvFile())
	if err != nil && !os.IsNotExist(err) {
		return "", "", errors.New("canonical secrets unavailable")
	}
	compute := p.Automation.CloudKeyFile
	write := func(key, name string) (string, error) {
		value := strings.TrimSpace(values[key])
		if value == "" {
			return "", nil
		}
		if strings.ContainsAny(value, "\r\n\x00") {
			return "", errors.New("invalid provider credential")
		}
		file := filepath.Join(directory, name)
		if err := os.WriteFile(file, []byte(value), 0600); err != nil {
			return "", err
		}
		return file, nil
	}
	if values["ULTRA_VULTR_API_KEY"] != "" {
		compute, err = write("ULTRA_VULTR_API_KEY", "compute-key")
		if err != nil {
			return "", "", err
		}
	}
	dns := ""
	if p.Automation.DNS != nil {
		dns, err = write("ULTRA_VULTR_DNS_API_KEY", "dns-key")
		if err != nil {
			return "", "", err
		}
		if dns == "" {
			return "", "", errors.New("ULTRA_VULTR_DNS_API_KEY missing from canonical secrets")
		}
	}
	return compute, dns, nil
}
