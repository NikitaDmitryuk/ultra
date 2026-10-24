package deployansible

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// Keep legacy integration fixtures rootless. This changes only the private
// exported fixture bytes before computing the execution binding, never the
// production namespace or embedded source.
func init() {
	executionFenceDirectory = func(directory string) string {
		root := filepath.Join(filepath.Dir(directory), ".execution-namespace")
		controller := filepath.Join(directory, "bundle", "controller.py")
		if source, err := os.ReadFile(controller); err == nil {
			quoted, _ := json.Marshal(root)
			replacement := "TEST_EXECUTION_NAMESPACE = True\nEXECUTION_ROOT = Path(" + string(quoted) + ")"
			changed := strings.Replace(string(source), "EXECUTION_ROOT = Path('/var/lib/ultra-ansible')", replacement, 1)
			if changed != string(source) {
				_ = os.WriteFile(controller, []byte(changed), 0600)
			}
		}
		return root
	}
}
