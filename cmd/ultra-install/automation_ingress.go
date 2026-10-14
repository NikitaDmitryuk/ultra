package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

func ansibleIngress(ctx context.Context, p *installplan.InstallPlan, inventory map[string]any, directory, python, executable, action string, operationVars map[string]any) error {
	return ansibleIngressOperation(ctx, p, inventory, directory, python, executable, action, operationVars, false, "")
}

// Only bootstrap operator re-invocation retries a frozen failed ingress stage.
func ansibleBootstrapIngress(ctx context.Context, p *installplan.InstallPlan, inventory map[string]any, directory, python, executable, action string, operationVars map[string]any, originals ...string) error {
	if action != "prepare" && action != "activate" && action != "adopt" {
		return errors.New("invalid bootstrap ingress action")
	}
	original := ""
	if len(originals) > 0 {
		original = originals[0]
	}
	return ansibleIngressOperation(ctx, p, inventory, directory, python, executable, action, operationVars, true, original)
}

func ansibleIngressOperation(ctx context.Context, p *installplan.InstallPlan, inventory map[string]any, directory, python, executable, action string, operationVars map[string]any, retry bool, original string) error {
	if p.Automation == nil || p.Automation.Ingress == nil {
		return nil
	}
	if action != "prepare" && action != "stage" && action != "activate" && action != "rollback" && action != "experiment" && action != "status" && action != "notice" && action != "adopt" {
		return errors.New("invalid ingress action")
	}
	var plan map[string]any
	raw, err := json.Marshal(p.Automation.Ingress)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(raw, &plan); err != nil {
		return err
	}
	variables := map[string]any{}
	for key, value := range operationVars {
		variables[key] = value
	}
	variables["ultra_ingress"] = plan
	variables["ultra_ingress_action"] = action
	transactionDirectory := directory
	if original != "" {
		transactionDirectory = original
	}
	transactionHash := sha256.Sum256([]byte(transactionDirectory))
	variables["ultra_ingress_transaction"] = "/var/lib/ultra-ingress/ansible-" + hex.EncodeToString(transactionHash[:])
	variables["ultra_ingress_email"] = p.Automation.Ingress.Email
	variables["ultra_ingress_domains"] = uniqueIngressDomains(p.Automation.Ingress.Domain, p.Bot.Domain, p.PublicSubscriptionDomain())
	variables["ultra_bot_domain"] = p.Bot.Domain
	variables["ultra_bot_port"] = p.Bot.Port
	variables["ultra_subscription_domain"] = p.PublicSubscriptionDomain()
	variables["ultra_subscription_enabled"] = p.Automation.Ingress.ForwardHost == ""
	variables["ultra_bridge_ipv4"] = p.Automation.BridgeIPv4
	if p.Automation.Ingress.ForwardHost != "" {
		raw, err := json.Marshal(inventory)
		if err != nil {
			return err
		}
		var independent map[string]any
		if err = json.Unmarshal(raw, &independent); err != nil {
			return err
		}
		children := independent["all"].(map[string]any)["children"].(map[string]any)
		children["forward_ingress"] = map[string]any{"hosts": map[string]any{"subscription_forward": map[string]any{"ansible_host": p.Automation.Ingress.ForwardHost}}}
		inventory = independent
		variables["ultra_forward_bridge_ipv4"] = p.Automation.BridgeIPv4
		variables["ultra_forward_domain"] = p.Bot.Domain
		variables["ultra_forward_bot_port"] = p.Bot.Port
	}
	if action == "prepare" || action == "stage" || action == "activate" || action == "rollback" {
		if err = prepareAnsibleDNS(p, variables); err != nil {
			return err
		}
	}
	if original != "" {
		source, sourceErr := bootstrapMutationSource(filepath.Dir(original), filepath.Base(original))
		if sourceErr != nil {
			return sourceErr
		}
		_, err = deployansible.RunLocalRetryFailedPinned(ctx, "ingress", inventory, variables, directory, source, python, executable)
	} else if retry {
		_, err = deployansible.RunLocalRetryFailed(ctx, "ingress", inventory, variables, directory, python, executable)
	} else {
		_, err = deployansible.RunLocal(ctx, "ingress", inventory, variables, directory, python, executable)
	}
	return err
}

func uniqueIngressDomains(values ...string) []string {
	result := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func applyConfiguredIngress(file, action string) error {
	p, err := installplan.LoadConfig(file)
	if err != nil {
		return err
	}
	if p.Automation == nil || p.Automation.Ingress == nil {
		return errors.New("canonical owned ingress policy required")
	}
	stateRoot, err := bootstrapStateRoot()
	if err != nil {
		return err
	}
	if err = ensurePrivateBootstrapDirectory(stateRoot); err != nil {
		return err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(append(raw, []byte(action)...))
	planRoot := filepath.Join(stateRoot, "configured-ingress-"+hex.EncodeToString(hash[:]))
	if err = ensurePrivateBootstrapDirectory(planRoot); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, operatorRelease, err := withBootstrapOperatorLock(ctx, stateRoot)
	if err != nil {
		return err
	}
	defer operatorRelease()
	var directory string
	if action == "status" {
		directory, err = os.MkdirTemp(stateRoot, "ingress-status-")
		if err == nil {
			defer func() {
				if err := os.RemoveAll(directory); err != nil {
					fmt.Fprintln(os.Stderr, "ingress_private_cleanup_failed")
				}
			}()
		}
	} else {
		directory, err = beginBootstrapAttempt(planRoot)
	}
	if err != nil {
		return err
	}
	lockDirectory, err := freezeBootstrapExecution(p, directory, stateRoot)
	if err != nil {
		return err
	}
	ctx, release, err := withFrozenLifecycleLock(ctx, p, lockDirectory, directory)
	if err != nil {
		return err
	}
	defer release()
	bridgeOnly := *p
	bridgeOnly.Exits = nil
	bridgeOnly.Database.Enabled = false
	python := "/usr/bin/python3"
	executable := os.Getenv("ULTRA_ANSIBLE_EXECUTABLE")
	if executable == "" {
		executable = "/opt/ultra-ansible/current/venv/bin/ansible-playbook"
	}
	gateInventory, err := bootstrapInventory(&bridgeOnly, directory)
	if err != nil {
		return err
	}
	mutating := action != "status"
	if mutating {
		if err = ansibleLifecycle(ctx, p, gateInventory, directory, python, executable, "applying", true); err != nil {
			return err
		}
	}
	inventory, _, err := inspectBootstrap(ctx, &bridgeOnly, directory, python, executable, lockDirectory)
	if err != nil {
		return err
	}
	if err = ansibleIngress(ctx, p, inventory, filepath.Join(directory, "apply"), python, executable, action, map[string]any{"ultra_lock_directory": lockDirectory}); err != nil {
		return err
	}
	if mutating {
		if err = ansibleLifecycle(ctx, p, inventory, directory, python, executable, "released", false); err != nil {
			return err
		}
	}
	if !mutating {
		return nil
	}
	return completeBootstrapAttempt(planRoot, directory)
}
