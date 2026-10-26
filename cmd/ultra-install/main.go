// Command ultra-install provides subcommand-based planning and Ansible installation.
package main

import (
	"fmt"
	"os"
)

func main() {
	args := os.Args[1:]
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		fmt.Println(
			"Usage: ultra-install <command> [options]\nUse make deploy for production replacement, or <command> --help for command options.",
		)
		return
	}
	if handlePlanSubcommand(args) {
		return
	}
	fmt.Fprintln(os.Stderr, "ultra-install: unknown command; use ultra-install --help")
	os.Exit(2)
}
