package main

import "errors"

// The former workflow moved a local primary with the bridge. A dedicated DB
// must never be overwritten as a side effect of moving a VPN node.
func runBridgeMigrationCommand(_ []string) {
	exitOnErr("bridge migration", errors.New("legacy_bridge_migration_unavailable_with_dedicated_database"))
}
