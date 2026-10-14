// Package ansibleassets contains the versioned infrastructure playbooks.
package ansibleassets

import "embed"

// Bundle contains source files only, never inventory or credentials.
//
//go:embed ansible.cfg playbooks roles library callback_plugins controller.py requirements.txt
var Bundle embed.FS
