package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// Ingress changes reuse the existing SSH transport and preserve the remote application state.
func runIngressCommand(args []string) {
	flags := flag.NewFlagSet("ultra-install ingress", flag.ExitOnError)
	action := flags.String("action", "status", "stage, activate, retire-experiment, rollback, notice or status")
	planFile := flags.String("plan", "", "public ingress plan JSON")
	canonical := flags.String("config", "", "canonical deployment configuration, exclusive with manual targets/plan")
	host := flags.String("host", "", "bridge SSH host")
	user := flags.String("user", "root", "SSH user")
	identity := flags.String("identity", "", "SSH identity file")
	knownHosts := flags.String("known-hosts", "", "verified known_hosts file")
	binary := flags.String("relay-binary", "", "deprecated: update pinned release before ingress changes")
	_ = flags.Parse(args)
	if *canonical != "" {
		if *host != "" || *planFile != "" || *identity != "" || *knownHosts != "" || *binary != "" {
			exitOnErr("ingress config", fmt.Errorf("config is exclusive with manual ingress options"))
		}
		exitOnErr("configured Ansible ingress", applyConfiguredIngress(*canonical, *action))
		return
	}
	if *action == "retire-experiment" {
		exitOnErr("ingress config", fmt.Errorf("retire-experiment requires canonical install.config"))
	}
	if *host == "" || *planFile == "" || *identity == "" || !filepath.IsAbs(*knownHosts) {
		exitOnErr("ingress inputs", fmt.Errorf("host, plan, identity and absolute verified known-hosts required"))
	}
	if *binary != "" {
		exitOnErr("ingress binary", fmt.Errorf("install a compatible pinned release with upgrade before changing ingress"))
	}
	switch *action {
	case "stage", "activate", "retire-experiment", "rollback", "status", "notice":
	default:
		exitOnErr("ingress action", fmt.Errorf("invalid ingress action"))
	}
	raw, err := os.ReadFile(*planFile)
	exitOnErr("ingress plan", err)
	if len(raw) > 16384 {
		exitOnErr("ingress plan", fmt.Errorf("plan too large"))
	}
	var settings map[string]any
	exitOnErr("ingress plan", json.Unmarshal(raw, &settings))
	p := &installplan.InstallPlan{
		SSH:    installplan.SSHConfig{User: *user, Identity: *identity},
		Bridge: installplan.BridgeConfig{SSHHost: *host, Address: *host, RemoteDir: "/etc/ultra-relay"},
	}
	stateRoot, err := bootstrapStateRoot()
	exitOnErr("ingress state", err)
	exitOnErr("private ingress state", ensurePrivateBootstrapDirectory(stateRoot))
	sum := sha256.Sum256(append(raw, []byte(*host+"|"+*action)...))
	planRoot := filepath.Join(stateRoot, "ingress-"+hex.EncodeToString(sum[:]))
	exitOnErr("private ingress operation", ensurePrivateBootstrapDirectory(planRoot))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, operatorRelease, err := withBootstrapOperatorLock(ctx, stateRoot)
	exitOnErr("ingress operator serialization", err)
	defer operatorRelease()
	directory, err := beginBootstrapAttempt(planRoot)
	exitOnErr("ingress attempt", err)
	lockDirectory, err := freezeBootstrapExecution(p, directory, stateRoot)
	exitOnErr("ingress execution mode", err)
	ctx, release, err := withFrozenLifecycleLock(ctx, p, lockDirectory, directory)
	exitOnErr("ingress operation lease", err)
	defer release()
	exitOnErr("ingress SSH pins", os.Setenv("ULTRA_INSTALL_SSH_KNOWN_HOSTS", *knownHosts))
	python := "/usr/bin/python3"
	executable := os.Getenv("ULTRA_ANSIBLE_EXECUTABLE")
	if executable == "" {
		executable = "/opt/ultra-ansible/current/venv/bin/ansible-playbook"
	}
	gateInventory, err := bootstrapInventory(p, directory)
	exitOnErr("ingress fixed inventory", err)
	if *action != "status" {
		exitOnErr("ingress fleet reservation", ansibleLifecycle(ctx, p, gateInventory, directory, python, executable, "applying", true))
	}
	inventory, inspection, err := inspectBootstrap(ctx, p, directory, python, executable, lockDirectory)
	exitOnErr("ingress inspection", err)
	environment, err := inspection["bridge"].file("environment")
	exitOnErr("ingress runtime environment", err)
	botDomain := ""
	botPort := 8444
	for _, line := range strings.Split(string(environment), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if key == "ULTRA_BOT_DOMAIN" {
			botDomain = strings.Trim(value, "\"'")
		}
		if key == "ULTRA_BOT_PORT" {
			botPort, err = strconv.Atoi(value)
			exitOnErr("bot port", err)
		}
	}
	domain, _ := settings["domain"].(string)
	email, _ := settings["email"].(string)
	variables := map[string]any{
		"ultra_lock_directory":       lockDirectory,
		"ultra_ingress":              settings,
		"ultra_ingress_action":       *action,
		"ultra_ingress_transaction":  "/var/lib/ultra-ingress/ansible-" + hex.EncodeToString(sum[:]) + "-" + filepath.Base(directory),
		"ultra_ingress_domains":      uniqueIngressDomains(domain, botDomain),
		"ultra_ingress_email":        email,
		"ultra_bot_domain":           botDomain,
		"ultra_bot_port":             botPort,
		"ultra_subscription_enabled": false,
		"ultra_subscription_domain":  botDomain,
		"ultra_bridge_ipv4":          "127.0.0.1",
	}
	_, err = deployansible.RunLocal(ctx, "ingress", inventory, variables, filepath.Join(directory, "apply"), python, executable)
	exitOnErr("Ansible ingress "+*action, err)
	if *action != "status" {
		exitOnErr("ingress fleet release", ansibleLifecycle(ctx, p, inventory, directory, python, executable, "released", false))
	}
	exitOnErr("ingress completion", completeBootstrapAttempt(planRoot, directory))
	fmt.Println("ingress " + *action + ": ready")
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
