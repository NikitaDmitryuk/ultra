package cloudinstall

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

type deadlineConfigurer struct {
	call func(context.Context) (deployansible.Result, error)
}

func (deadlineConfigurer) Ready(context.Context) error { return nil }
func (c deadlineConfigurer) ConfigureExit(ctx context.Context, _, _ string, _ deployansible.ExitRequest) (deployansible.Result, error) {
	return c.call(ctx)
}

func TestConfigurationObservationOutlivesControllerExecutionBudget(t *testing.T) {
	var observed context.Context
	p := Provisioner{Configurer: deadlineConfigurer{call: func(ctx context.Context) (deployansible.Result, error) {
		observed = ctx
		deadline, ok := ctx.Deadline()
		// A successful controller completion after the former five-minute limit
		// must still be observable, including the controller's full 900s budget.
		if !ok || time.Until(deadline) <= 15*time.Minute {
			t.Fatal("caller expires before durable controller can finish")
		}
		return deployansible.Result{CertPin: "terminal-result"}, nil
	}}}
	result, err := p.configureExitJob(context.Background(), "job", "binary", deployansible.ExitRequest{})
	if err != nil || result.CertPin != "terminal-result" {
		t.Fatal("terminal result lost", err)
	}
	if !errors.Is(observed.Err(), context.Canceled) {
		t.Fatal("observation timer leaked")
	}
}

func TestConfigurationObservationRespectsCallerCancellation(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	p := Provisioner{
		Configurer: deadlineConfigurer{
			call: func(ctx context.Context) (deployansible.Result, error) { return deployansible.Result{}, ctx.Err() },
		},
	}
	if _, err := p.configureExitJob(parent, "job", "binary", deployansible.ExitRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	parent, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	p.Configurer = deadlineConfigurer{call: func(ctx context.Context) (deployansible.Result, error) {
		a, _ := parent.Deadline()
		b, _ := ctx.Deadline()
		if !a.Equal(b) {
			t.Fatal("caller deadline extended")
		}
		return deployansible.Result{}, nil
	}}
	if _, err := p.configureExitJob(parent, "job", "binary", deployansible.ExitRequest{}); err != nil {
		t.Fatal(err)
	}
}
