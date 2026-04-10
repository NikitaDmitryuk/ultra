package install

import _ "embed"

//go:embed scripts/system-setup.sh
var systemSetupScript string

// SystemSetupScript returns a bash script that configures locale and timezone on a remote node.
//
// What it does:
//   - Sets system timezone to UTC (idempotent via timedatectl or /etc/localtime symlink).
//   - Generates en_US.UTF-8 locale and writes it to /etc/default/locale so that all
//     subsequent bash -lc sessions export LC_ALL/LANG automatically.
//
// Without this, apt-get/nginx/perl print "Setting locale failed" warnings during every
// package install because the server ships without a generated locale.
//
// Idempotent — safe to run on an already-configured node.
func SystemSetupScript() string {
	return systemSetupScript
}

// SetupSystem runs SystemSetupScript on the remote host over SSH.
func SetupSystem(sshUser, host, identity string) error {
	return RunSSH(sshUser, host, identity, SystemSetupScript())
}
