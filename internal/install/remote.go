package install

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os/exec"
	"strconv"

	"github.com/NikitaDmitryuk/ultra/internal/operatorssh"
)

// Remote is a bounded, non-logging transport used by provisioning workers.
// Each cloud instance has its own known_hosts file; changed host keys are rejected.
type Remote struct {
	Host, Identity, KnownHosts string
	RequireKnownHost           bool
}

func (r Remote) args() ([]string, error) {
	if net.ParseIP(r.Host) == nil || r.Identity == "" || r.KnownHosts == "" {
		return nil, errors.New("invalid SSH target")
	}
	checking := "StrictHostKeyChecking=accept-new"
	if r.RequireKnownHost {
		checking = "StrictHostKeyChecking=yes"
	}
	return []string{
		"-o",
		"BatchMode=yes",
		"-o",
		checking,
		"-o",
		"UserKnownHostsFile=" + r.KnownHosts,
		"-o",
		"ConnectTimeout=" + strconv.Itoa(operatorssh.DefaultPolicy.ProbeConnectTimeoutSeconds),
		"-o",
		"ServerAliveInterval=5",
		"-o",
		"ServerAliveCountMax=2",
		"-i",
		r.Identity,
	}, nil
}
func (r Remote) Run(ctx context.Context, script string) ([]byte, error) {
	args, e := r.args()
	if e != nil {
		return nil, e
	}
	args = append(args, "root@"+r.Host, "bash -s")
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Stdin = bytes.NewBufferString(script)
	out, e := cmd.Output()
	if e != nil {
		return nil, errors.New("remote operation failed")
	}
	return out, nil
}
