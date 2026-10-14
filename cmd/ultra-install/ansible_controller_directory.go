package main

import "path/filepath"

// New ownership-managed runtimes must not overwrite a legacy version directory
// that predates durable ownership receipts. Versions are validated by preflight.
func managedControllerDirectory(version string) string {
	return filepath.Join("/opt/ultra-ansible/releases", "managed-"+version)
}
