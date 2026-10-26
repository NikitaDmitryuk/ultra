package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestBootstrapInventoryProjectsBoundedSSHTimeout(t *testing.T) {
	for _, seconds := range []int{0, 1, 30, 300, -1, 301} {
		t.Run(strconv.Itoa(seconds), func(t *testing.T) {
			directory := t.TempDir()
			pins := filepath.Join(directory, "pins")
			if err := os.WriteFile(pins, []byte("fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			p := installplan.LegacyValuesToPlan(
				map[string]string{
					"BRIDGE_IP":         "192.0.2.10",
					"MAIN_EXIT_IP":      "192.0.2.20",
					"DATABASE_IP":       "192.0.2.30",
					"BRIDGE_SSH_KEY":    "/keys/bridge",
					"MAIN_EXIT_SSH_KEY": "/keys/exit",
					"DATABASE_SSH_KEY":  "/keys/database",
				},
			)
			completeDeploymentFixture(p, "/release", pins)
			p.SSH.ConnectTimeoutSec = seconds
			inventory, err := bootstrapInventory(p, directory)
			if seconds < 0 || seconds > 300 {
				if err == nil {
					t.Fatal("unbounded SSH timeout accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(inventory)
			if err != nil {
				t.Fatal(err)
			}
			// Resolve inheritance with Ansible itself: direct bridge/exit and the DB
			// host used by the pinned tunnel must receive the same connection timeout.
			var serialized struct {
				All struct {
					Vars     map[string]any `json:"vars"`
					Children map[string]struct {
						Hosts map[string]map[string]any `json:"hosts"`
					} `json:"children"`
				} `json:"all"`
			}
			if err := json.Unmarshal(raw, &serialized); err != nil {
				t.Fatal(err)
			}
			want := seconds
			if want == 0 {
				want = 10
			}
			if serialized.All.Vars["ansible_ssh_timeout"] != float64(want) {
				t.Fatal("serialized connection timeout missing")
			}
			for group, alias := range map[string]string{"bridge": "bridge", "exits": "exit_0", "databases": "database"} {
				host := serialized.All.Children[group].Hosts[alias]
				if host == nil {
					t.Fatalf("missing host %s", alias)
				}
				if override, found := host["ansible_ssh_timeout"]; found && override != float64(want) {
					t.Fatalf("host %s overrides configured timeout", alias)
				}
			}
			args := serialized.All.Vars["ansible_ssh_common_args"].(string)
			if !strings.Contains(args, "StrictHostKeyChecking=yes") || !strings.Contains(args, "ControlMaster=no") {
				t.Fatal("pinned transport changed")
			}
			// Ansible is installed in the dedicated integration job, not the Go job.
			t.Run("ansible_resolution", func(t *testing.T) {
				if err := exec.Command("python3", "-c", "import ansible").Run(); err != nil {
					t.Skip("Ansible unavailable; serialized inventory assertions passed")
				}
				python := `import json,sys
from ansible.inventory.manager import InventoryManager
from ansible.parsing.dataloader import DataLoader
from ansible.vars.manager import VariableManager
inventory=json.load(sys.stdin)
from pathlib import Path
p=Path(sys.argv[1]);p.write_text(json.dumps(inventory))
loader=DataLoader();manager=InventoryManager(loader=loader,sources=[str(p)])
variables=VariableManager(loader=loader,inventory=manager)
for name in ('bridge','exit_0','database'):
 values=variables.get_vars(host=manager.get_host(name))
 assert values['ansible_ssh_timeout']==int(sys.argv[2]),(name,values.get('ansible_ssh_timeout'))
 assert 'StrictHostKeyChecking=yes' in values['ansible_ssh_common_args']
 assert 'ControlMaster=no' in values['ansible_ssh_common_args']
`
				command := exec.Command("python3", "-c", python, filepath.Join(directory, "inventory.json"), strconv.Itoa(want))
				command.Stdin = strings.NewReader(string(raw))
				command.Env = append(os.Environ(), "ANSIBLE_LOCAL_TEMP="+filepath.Join(directory, "ansible-tmp"))
				if output, err := command.CombinedOutput(); err != nil {
					t.Fatalf("serialized Ansible inventory: %v %s", err, output)
				}
			})
		})
	}
}
