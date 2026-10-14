package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

// A fixed root-only SSH entry point. It never accepts inventory, paths to
// playbooks, shell commands, or secrets. A disconnected operator does not
// release its persistent reservation; resume explicitly with the same UUID.
func runAnsibleLease(args []string) {
	flags := flag.NewFlagSet("ansible-lease", flag.ExitOnError)
	socket := flags.String("socket", "/run/ultra-ansible/controller.sock", "local controller socket")
	id := flags.String("id", "", "persistent lifecycle UUID")
	resume := flags.Bool("resume-frozen", false, "resume an already reserved immutable attempt")
	phase := flags.String("phase", "", "applying, checking, or released")
	_ = flags.Parse(args)
	if os.Geteuid() != 0 {
		exitOnErr("Ansible lease", fmt.Errorf("root operator required"))
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	client := deployansible.Client{Socket: *socket}
	if *resume {
		if *phase != "applying" {
			exitOnErr("Ansible lease", fmt.Errorf("resume requires applying phase"))
		}
		exitOnErr("Ansible lease", client.ResumeLifecycleWithOperationLock(ctx, *id))
	} else {
		exitOnErr("Ansible lease", client.Lifecycle(ctx, *id, *phase))
	}
	fmt.Println("Ansible lifecycle:", *phase)
}
