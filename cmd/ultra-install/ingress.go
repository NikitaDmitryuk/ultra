package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/install"
)

// Ingress changes reuse the existing SSH transport and preserve the remote application state.
func runIngressCommand(args []string) {
	fs := flag.NewFlagSet("ultra-install ingress", flag.ExitOnError)
	action := fs.String("action", "status", "stage, activate, experiment, rollback, notice or status")
	planFile := fs.String("plan", "", "public ingress plan JSON")
	host := fs.String("host", "", "bridge SSH host")
	user := fs.String("user", "root", "SSH user")
	identity := fs.String("identity", "", "SSH identity file")
	knownHosts := fs.String("known-hosts", "", "verified known_hosts file")
	binary := fs.String("relay-binary", "", "local relay binary to stage")
	_ = fs.Parse(args)
	exitOnErr("strict SSH", os.Setenv("ULTRA_INSTALL_SSH_STRICT_HOST_KEY", "yes"))
	if *knownHosts != "" {
		exitOnErr("known hosts", os.Setenv("ULTRA_INSTALL_SSH_KNOWN_HOSTS", *knownHosts))
	}
	if *host == "" || *planFile == "" {
		fmt.Fprintln(os.Stderr, "ingress: -host and -plan required")
		os.Exit(2)
	}
	switch *action {
	case "stage", "activate", "experiment", "rollback", "status", "notice":
	default:
		fmt.Fprintln(os.Stderr, "ingress: invalid action")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*planFile)
	exitOnErr("ingress plan", err)
	if len(raw) > 16384 {
		exitOnErr("ingress plan", fmt.Errorf("plan too large"))
	}
	var p map[string]any
	exitOnErr("ingress plan", json.Unmarshal(raw, &p))
	remote := "/var/lib/ultra-ingress/relay.next"
	if *binary != "" {
		exitOnErr("ingress binary", install.RunSSH(*user, *host, *identity, "install -d -m 700 /var/lib/ultra-ingress"))
		exitOnErr("ingress binary", install.SCP(*identity, filepath.Clean(*binary), *user, *host, remote))
		exitOnErr("ingress binary", install.RunSSH(*user, *host, *identity, "chmod 755 "+remote))
	}
	p["binary"] = remote
	raw, err = json.Marshal(p)
	exitOnErr("ingress plan", err)
	script := base64.StdEncoding.EncodeToString([]byte(install.XHTTPIngressScript))
	payload := base64.StdEncoding.EncodeToString(raw)
	command := "python3 -c " + shellQuote("import base64,sys;sys.argv=['ingress',"+fmt.Sprintf("%q", *action)+","+fmt.Sprintf("%q", payload)+"];exec(compile(base64.b64decode("+fmt.Sprintf("%q", script)+"),'ultra-ingress','exec'))")
	exitOnErr("ingress "+*action, install.RunSSH(*user, *host, *identity, command))
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
