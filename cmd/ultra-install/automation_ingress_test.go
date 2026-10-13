package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestAutomationPythonCommandQuoting(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 required for the real shell/Python boundary")
	}
	marker := filepath.Join(t.TempDir(), "unexpected-command")
	values := []string{
		"quotes: '\" and \\ backslash\nnext line",
		"'; touch " + marker + "; #",
		"$(touch " + marker + ") `touch " + marker + "`",
		"Кириллица / emoji 🦊 / \u2028 / \t / \r",
	}
	for _, value := range values {
		// JSON settings take the same two decoding steps as ingress settings.
		settings, err := json.Marshal(map[string]string{"value": value})
		if err != nil {
			t.Fatal(err)
		}
		source := "import json\nsettings=json.loads(" + pythonString(string(settings)) + ")\nprint(json.dumps(settings))\n"
		// OpenSSH executes the command through a shell; RunSSH additionally
		// wraps it in bash -lc. Keep both parsing boundaries in this regression.
		command := "bash -c " + shellQuote(automationPythonCommand(source))
		output, err := exec.Command("sh", "-c", command).CombinedOutput()
		if err != nil {
			t.Fatalf("shell/Python round trip failed: %v: %s", err, output)
		}
		var got map[string]string
		if err := json.Unmarshal(output, &got); err != nil || got["value"] != value {
			t.Fatalf("settings changed: got %q, want %q (decode: %v)", output, value, err)
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("settings executed a shell command: %v", err)
	}
}
