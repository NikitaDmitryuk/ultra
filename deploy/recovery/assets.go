// Package recoveryassets bundles the operator recovery entrypoints with ultra-install.
package recoveryassets

import "embed"

// Scripts contains source only; no generated state, credentials, or recovery bundles.
//
//go:embed domain_cutover.py dns.py recovery.py recovery_key.py restore.py restore_common.py restore_host.py restore_peer.py
var Scripts embed.FS
