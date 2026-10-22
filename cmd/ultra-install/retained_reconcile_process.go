package main

import (
	"bytes"
	"path/filepath"
	"strings"
)

func retainedExecutorCommand(raw []byte) bool {
	args := bytes.Split(bytes.TrimRight(raw, "\x00"), []byte{0})
	if len(args) == 0 {
		return false
	}
	executable := filepath.Base(string(args[0]))
	switch executable {
	case "ultra-install", "ansible-playbook", "controller.py", "reconcile.py":
		return true
	}
	if len(args) > 1 {
		switch string(args[1]) {
		case "ansible-controller",
			"ansible-run",
			"ansible-exit",
			"rebuild-retained-primary",
			"operator-upgrade",
			"deploy-operation",
			"bridge-preflight-proof",
			"recovery-prepare",
			"ansible-retry-bootstrap",
			"ansible-bootstrap-components",
			"retained-primary-reconcile",
			"apply-remote":
			return true
		}
	}
	if strings.HasPrefix(executable, "python") {
		for _, arg := range args[1:] {
			if strings.HasPrefix(string(arg), "-") {
				continue
			}
			switch filepath.Base(string(arg)) {
			case "controller.py", "reconcile.py", "ansible-playbook":
				return true
			}
		}
	}
	return false
}
