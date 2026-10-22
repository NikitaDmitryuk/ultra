package cloudinstall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	_ "unsafe" // Test-only link to the fixed production namespace resolver.
)

// Cloud integration tests run the real broker/controller in a private fixture.
// No production override or configurable fence namespace is introduced.
//
//go:linkname fixtureExecutionNamespace github.com/NikitaDmitryuk/ultra/internal/deployansible.executionFenceDirectory
var fixtureExecutionNamespace func(string) string

func init() {
	fixtureExecutionNamespace = func(directory string) string {
		root := filepath.Join(filepath.Dir(filepath.Dir(directory)), ".execution-namespace")
		controller := filepath.Join(directory, "bundle", "controller.py")
		if source, err := os.ReadFile(controller); err == nil {
			quoted, _ := json.Marshal(root)
			changed := strings.Replace(
				string(source),
				"EXECUTION_ROOT = Path('/var/lib/ultra-ansible')",
				"EXECUTION_ROOT = Path("+string(quoted)+")",
				1,
			)
			if changed != string(source) {
				_ = os.WriteFile(controller, []byte(changed), 0600)
			}
		}
		return root
	}
}
