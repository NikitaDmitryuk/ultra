package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	_ "unsafe" // Required only for a test-binary link to the internal resolver.
)

// The installer integration package links deployansible without that package's
// *_test.go fixture initializer. Rebind its private resolver in this test binary
// rather than introducing a production namespace override or replacing RunLocal.
//
//go:linkname fixtureExecutionNamespace github.com/NikitaDmitryuk/ultra/internal/deployansible.executionFenceDirectory
var fixtureExecutionNamespace func(string) string

var fixturePriorControllerComments sync.Map

func init() {
	lastRoot := ""
	var mutex sync.Mutex
	fixtureExecutionNamespace = func(directory string) string {
		mutex.Lock()
		defer mutex.Unlock()
		if directory == "" {
			if lastRoot == "" {
				lastRoot, _ = os.MkdirTemp("", "ultra-installer-execution-")
			}
			return lastRoot
		}
		base := filepath.Dir(directory)
		raw, err := os.ReadFile(filepath.Join(directory, "request.json"))
		if err == nil {
			var request struct {
				Variables map[string]any `json:"variables"`
			}
			if json.Unmarshal(raw, &request) == nil {
				if configured, ok := request.Variables["ultra_lock_directory"].(string); ok && filepath.IsAbs(configured) {
					base = configured
				}
			}
		}
		if _, ok := fixturePriorControllerComments.Load(base); ok {
			controller := filepath.Join(directory, "bundle", "controller.py")
			if raw, err := os.ReadFile(controller); err == nil && !strings.Contains(string(raw), "# original prior-version bundle") {
				_ = os.WriteFile(controller, append(raw, []byte("\n# original prior-version bundle\n")...), 0600)
			}
		}
		root := filepath.Join(base, ".execution-namespace")
		lastRoot = root
		return root
	}
}

// Keep pinned fixture bundles byte-identical. Only the test interpreter imports
// the controller with its internal namespace argument replaced in memory.
func TestMain(m *testing.M) {
	python, err := exec.LookPath("python3")
	if err != nil {
		os.Exit(m.Run())
	}
	resolved, err := exec.Command(python, "-c", "import sys;print(sys.executable)").Output()
	if err == nil {
		python = strings.TrimSpace(string(resolved))
	}
	directory, err := os.MkdirTemp("", "ultra-installer-python-")
	if err != nil {
		panic(err)
	}
	wrapper := filepath.Join(directory, "python3")
	quoted, _ := json.Marshal(python)
	source := "#!" + python + "\n" + `import sys, os, pathlib, json, importlib.util
_real_python = ` + string(quoted) + `
if len(sys.argv)>1 and pathlib.Path(sys.argv[1]).name=='controller.py' and '--job' in sys.argv:
    sys.dont_write_bytecode=True
    source=pathlib.Path(sys.argv[1])
    job=pathlib.Path(sys.argv[sys.argv.index('--job')+1])
    request=json.loads((job/'request.json').read_text())
    base=pathlib.Path(request.get('variables',{}).get('ultra_lock_directory',str(job.parent)))
    spec=importlib.util.spec_from_file_location('fixture_execution_controller',source)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.EXECUTION_ROOT=base/'.execution-namespace'
    module.TEST_EXECUTION_NAMESPACE=True
    sys.argv=sys.argv[1:]
    module.main()
else:
    os.execv(_real_python,[_real_python]+sys.argv[1:])
`
	if err = os.WriteFile(wrapper, []byte(source), 0700); err != nil {
		panic(err)
	}
	ansibleControllerPython = wrapper
	_ = os.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	status := m.Run()
	_ = os.RemoveAll(directory)
	os.Exit(status)
}

// Existing installer fixtures replace only Ansible's remote task execution.
// Model a normally acknowledged task failure using the real callback's final
// stats writer, rather than treating an unproven exit(1) as remote completion.
// Transport/cancellation fixtures deliberately do not use this prelude.
func withNormalAnsibleFailure(source string) []byte {
	prelude := `import sys as _fixture_sys, os as _fixture_os, json as _fixture_json, pathlib as _fixture_pathlib, types as _fixture_types, importlib.util as _fixture_import
_fixture_original_exit = _fixture_sys.exit
def _fixture_normal_exit(code=0):
    if code == 1 and _fixture_os.environ.get('ULTRA_EXECUTION_BINDING'):
        _fixture_base = _fixture_types.ModuleType('ansible.plugins.callback')
        _fixture_base.CallbackBase = object
        _fixture_sys.modules['ansible'] = _fixture_types.ModuleType('ansible')
        _fixture_sys.modules['ansible.plugins'] = _fixture_types.ModuleType('ansible.plugins')
        _fixture_sys.modules['ansible.plugins.callback'] = _fixture_base
        _fixture_root = _fixture_pathlib.Path(_fixture_os.environ['ULTRA_ANSIBLE_SOURCE_ROOT'])
        _fixture_spec = _fixture_import.spec_from_file_location('fixture_safe_result', _fixture_root/'callback_plugins'/'safe_result.py')
        _fixture_module = _fixture_import.module_from_spec(_fixture_spec)
        _fixture_spec.loader.exec_module(_fixture_module)
        _fixture_callback = _fixture_module.CallbackModule()
        _fixture_host = _fixture_types.SimpleNamespace(name='fixture_target')
        _fixture_task = _fixture_types.SimpleNamespace(_uuid='completed_fixture_task', async_val=0)
        _fixture_callback.execution_task(_fixture_host, _fixture_task)
        _fixture_callback.execution_task(_fixture_host, _fixture_task, True)
        _fixture_stats = _fixture_types.SimpleNamespace(processed={'fixture_target':1}, summarize=lambda host:{'failures':1,'unreachable':0})
        _fixture_callback.v2_playbook_on_stats(_fixture_stats)
        _fixture_original_exit(2)
    _fixture_original_exit(code)
_fixture_sys.exit = _fixture_normal_exit
`
	first, body, found := strings.Cut(source, "\n")
	if !found {
		return []byte(source)
	}
	return []byte(first + "\n" + prelude + body)
}
