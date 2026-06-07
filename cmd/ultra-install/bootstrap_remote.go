package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/install"
)

func loadRemoteBootstrapEntries(sshUser, bridgeHost, identity, remoteDir string) []exits.BootstrapEntry {
	remotePath := path.Join(remoteDir, exits.BootstrapFileName)
	script := fmt.Sprintf(`test -r %q && cat %q || true`, remotePath, remotePath)
	out, err := install.RunSSHOutput(sshUser, bridgeHost, identity, script)
	if err != nil {
		return nil
	}
	out = bytes.TrimSpace(out)
	if len(out) == 0 {
		return nil
	}
	var entries []exits.BootstrapEntry
	if err := json.Unmarshal(out, &entries); err != nil {
		return nil
	}
	return entries
}

func loadRemoteExitTunnelUUID(sshUser, exitHost, identity, remoteDir string) string {
	remotePath := path.Join(remoteDir, "spec.json")
	script := fmt.Sprintf(
		`python3 -c "import json; d=json.load(open(%q)); print(d.get('exit',{}).get('tunnel_uuid',''))" 2>/dev/null || true`,
		remotePath,
	)
	out, err := install.RunSSHOutput(sshUser, exitHost, identity, script)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func resolveExitTunnelUUID(
	priorBootstrap []exits.BootstrapEntry,
	sshUser, exitHost, identity, remoteDir, dialAddr string,
	port int,
) string {
	if u := exits.BootstrapTunnelUUID(priorBootstrap, dialAddr, port); u != "" {
		return u
	}
	if install.SSHReachable(sshUser, exitHost, identity) {
		if u := loadRemoteExitTunnelUUID(sshUser, exitHost, identity, remoteDir); u != "" {
			return u
		}
	}
	return ""
}
