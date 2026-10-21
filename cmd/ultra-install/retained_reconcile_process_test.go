package main

import (
	"strings"
	"testing"
)

func TestRetainedReconcileCensusDistinguishesPathsFromExecutors(t *testing.T) {
	for _, args := range [][]string{
		{"git", "diff", "--", "/workspace/cmd/ultra-install"},
		{"go", "test", "./cmd/ultra-install"},
	} {
		if retainedExecutorCommand([]byte(strings.Join(args, "\x00"))) {
			t.Fatalf("source inspection mistaken for executor: %v", args)
		}
	}
	for _, args := range [][]string{
		{"/usr/local/bin/ultra-install", "status"},
		{"/tmp/operator-tool", "retained-primary-reconcile", "inspect"},
		{"/tmp/operator-tool", "ansible-run"},
		{"/usr/bin/python3", "-u", "/opt/ultra/controller.py"},
		{"/usr/bin/python3", "-W", "ignore", "/opt/ultra/controller.py"},
		{"/usr/bin/python3", "-X", "dev", "/opt/ultra/reconcile.py"},
		{"/opt/runtime/bin/ansible-playbook", "playbook.yml"},
	} {
		if !retainedExecutorCommand([]byte(strings.Join(args, "\x00"))) {
			t.Fatalf("executor not fenced: %v", args)
		}
	}
}
