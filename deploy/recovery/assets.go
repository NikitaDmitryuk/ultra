// Package recoveryassets bundles the operator recovery entrypoints with ultra-install.
package recoveryassets

import "embed"

// Scripts contains source only; no generated state, credentials, or recovery bundles.
//
//go:embed *.py ssh_policy.json
var Scripts embed.FS
