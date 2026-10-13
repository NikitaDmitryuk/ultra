package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"

	"github.com/NikitaDmitryuk/ultra/internal/install"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func runAutomationCommand(action string, args []string) {
	fs := flag.NewFlagSet("ultra-install "+action, flag.ExitOnError)
	plan := fs.String("plan", "", "validated install plan; private file references only")
	configPath := fs.String("config", "", "canonical install.config path (exclusive with --plan)")
	_ = fs.Parse(args)
	p := readDeploymentOrExit(*plan, *configPath)
	exitOnErr("automation "+action, applyAutomation(p, action))
}

func applyAutomation(p *installplan.InstallPlan, action string) error {
	if err := installplan.ValidatePlan(p); err != nil {
		return err
	}
	if p.Automation == nil {
		return errors.New("automation configuration required")
	}
	a := p.Automation
	if action != "status" {
		if err := preflightAutomation(p); err != nil {
			return err
		}
	}
	if err := os.Setenv("ULTRA_INSTALL_SSH_STRICT_HOST_KEY", "yes"); err != nil {
		return err
	}
	if err := os.Setenv("ULTRA_INSTALL_SSH_KNOWN_HOSTS", a.KnownHostsFile); err != nil {
		return err
	}
	local, err := os.MkdirTemp("", "ultra-automation-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(local) //nolint:errcheck
	id := filepath.Base(local)
	remote := path.Join("/var/lib/ultra-automation/staging", id)
	ssh := func(command string) error {
		return install.RunSSH(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, command)
	}
	if err := ssh("install -d -m 700 " + shellQuote(remote)); err != nil {
		return errors.New("automation staging unavailable")
	}
	defer func() { _ = ssh("rm -rf -- " + shellQuote(remote)) }()
	upload := func(source, name string) error {
		return install.SCP(p.SSH.Identity, source, p.SSH.User, p.Bridge.SSHHost, path.Join(remote, name))
	}
	script := filepath.Join(local, "automation.py")
	if err := os.WriteFile(script, []byte(install.AutomationScript), 0600); err != nil {
		return err
	}
	if err := upload(script, "automation.py"); err != nil {
		return errors.New("automation script upload failed")
	}
	command := "python3 " + shellQuote(path.Join(remote, "automation.py")) + " --action " + shellQuote(action)
	if action == "status" {
		return ssh(command)
	}
	// Target architecture is authoritative; local operator architecture need not match.
	output, err := install.RunSSHOutput(p.SSH.User, p.Bridge.SSHHost, p.SSH.Identity, "dpkg --print-architecture")
	if err != nil {
		return errors.New("automation target architecture unavailable")
	}
	arch := string(output)
	for len(arch) > 0 && (arch[len(arch)-1] == '\n' || arch[len(arch)-1] == '\r') {
		arch = arch[:len(arch)-1]
	}
	if arch != "amd64" && arch != "arm64" {
		return errors.New("unsupported automation target architecture")
	}
	for _, name := range []string{"release-manifest.json", "ultra-recovery.tar.gz", "ultra-client-linux-" + arch, "ultra-relay-linux-amd64", "ultra-relay-linux-arm64", "ultra-bot-linux-" + arch} {
		if err := upload(filepath.Join(a.ReleaseDir, name), name); err != nil {
			return errors.New("automation release upload failed")
		}
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		return err
	}
	config["database"] = p.Database.Name
	if p.Database.Name == "" {
		config["database"] = "ultra_db"
	}
	config["spec"] = path.Join(p.Bridge.RemoteDir, "spec.json")
	if err := upload(a.KnownHostsFile, "known_hosts"); err != nil {
		return errors.New("automation known hosts upload failed")
	}
	config["known_hosts_file"] = path.Join(remote, "known_hosts")
	computeKey, dnsKey, err := prepareProviderSecrets(p, local)
	if err != nil {
		return err
	}
	if computeKey != "" {
		if err := upload(computeKey, "cloud-key"); err != nil {
			return errors.New("automation cloud key upload failed")
		}
		config["cloud_key_file"] = path.Join(remote, "cloud-key")
	}
	if dnsKey != "" {
		if err := upload(dnsKey, "dns-key"); err != nil {
			return errors.New("automation DNS key upload failed")
		}
		config["dns"].(map[string]any)["api_key_file"] = path.Join(remote, "dns-key")
	}
	payload, err := json.Marshal(config)
	if err != nil {
		return err
	}
	configPath := filepath.Join(local, "bootstrap.json")
	if err := os.WriteFile(configPath, payload, 0600); err != nil {
		return err
	}
	if err := upload(configPath, "bootstrap.json"); err != nil {
		return errors.New("automation configuration upload failed")
	}
	if err := ssh(command + " --config " + shellQuote(path.Join(remote, "bootstrap.json")) + " --release " + shellQuote(remote)); err != nil {
		return fmt.Errorf("full automation %s did not reach readiness", action)
	}
	return nil
}

// preflightAutomation verifies every supplied release asset before the installer mutates a host.
func preflightAutomation(p *installplan.InstallPlan) error {
	if !p.FullAutomation() {
		return nil
	}
	if err := installplan.ValidatePlan(p); err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(p.Automation.ReleaseDir, "release-manifest.json"))
	if err != nil {
		return errors.New("complete release manifest unavailable")
	}
	var manifest struct {
		Version      string   `json:"version"`
		Capabilities []string `json:"capabilities"`
		Assets       []struct {
			Name string `json:"name"`
			SHA  string `json:"sha256"`
			Size int64  `json:"size"`
		} `json:"assets"`
	}
	if json.Unmarshal(raw, &manifest) != nil || manifest.Version != p.Automation.Version {
		return errors.New("release version mismatch")
	}
	capable := false
	for _, capability := range manifest.Capabilities {
		capable = capable || capability == "service-access-v1"
	}
	if !capable {
		return errors.New("release lacks service-access-v1 capability")
	}
	seen := map[string]bool{}
	for _, asset := range manifest.Assets {
		if filepath.Base(asset.Name) != asset.Name || asset.Name == "." || seen[asset.Name] {
			return errors.New("invalid or repeated release asset")
		}
		seen[asset.Name] = true
		file, err := os.Open(filepath.Join(p.Automation.ReleaseDir, asset.Name))
		if err != nil {
			return errors.New("release asset missing")
		}
		hash := sha256.New()
		size, copyErr := io.Copy(hash, file)
		_ = file.Close()
		if copyErr != nil || size != asset.Size || hex.EncodeToString(hash.Sum(nil)) != asset.SHA {
			return errors.New("release checksum mismatch")
		}
	}
	for _, name := range []string{"ultra-relay-linux-amd64", "ultra-relay-linux-arm64", "ultra-bot-linux-amd64", "ultra-bot-linux-arm64", "ultra-client-linux-amd64", "ultra-client-linux-arm64", "ultra-recovery.tar.gz"} {
		if !seen[name] {
			return errors.New("incomplete automation release")
		}
	}
	return nil
}
