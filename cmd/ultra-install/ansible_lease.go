package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/google/uuid"
)

// A fixed root-only SSH entry point. It never accepts inventory, paths to
// playbooks, shell commands, or secrets. A disconnected operator does not
// release its persistent reservation; resume explicitly with the same UUID.
func runAnsibleLease(args []string) {
	if os.Geteuid() != 0 {
		exitOnErr("Ansible lease", fmt.Errorf("root operator required"))
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	exitOnErr("Ansible lease", runAnsibleLeaseCommand(ctx, args, os.Stdout))
}

// The entry point enforces the root peer requirement before dispatching here.
func runAnsibleLeaseCommand(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("ansible-lease", flag.ContinueOnError)
	flags.SetOutput(output)
	socket := flags.String("socket", "/run/ultra-ansible/controller.sock", "local controller socket")
	id := flags.String("id", "", "persistent lifecycle UUID")
	resume := flags.Bool("resume-frozen", false, "resume an already reserved immutable attempt")
	phase := flags.String("phase", "", "applying, checking, or released")
	retire := flags.Bool("retire", false, "permanently abandon an exact applying lifecycle UUID")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("ansible-lease does not accept positional arguments")
	}
	if *retire {
		incompatible := false
		flags.Visit(func(f *flag.Flag) {
			if f.Name == "phase" || f.Name == "resume-frozen" {
				incompatible = true
			}
		})
		if incompatible {
			return fmt.Errorf("retire cannot be combined with phase or resume-frozen")
		}
		parsed, err := uuid.Parse(*id)
		if err != nil || parsed.String() != *id {
			return fmt.Errorf("retire requires an exact canonical lifecycle UUID")
		}
	}
	client := deployansible.Client{Socket: *socket}
	if *retire {
		if err := client.RetireLifecycle(ctx, *id); err != nil {
			return err
		}
		_, err := fmt.Fprintln(output, "Ansible lifecycle retired:", *id)
		return err
	}
	if *resume {
		if *phase != "applying" {
			return fmt.Errorf("resume requires applying phase")
		}
		if err := client.ResumeLifecycleWithOperationLock(ctx, *id); err != nil {
			return err
		}
	} else {
		if err := client.Lifecycle(ctx, *id, *phase); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(output, "Ansible lifecycle:", *phase)
	return err
}
