package install

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os/exec"
	"strconv"
)

// Remote is a bounded, non-logging transport used by provisioning workers.
// Each cloud instance has its own known_hosts file; changed host keys are rejected.
type Remote struct{ Host, Identity, KnownHosts string }

func (r Remote) args() ([]string, error) {
	if net.ParseIP(r.Host) == nil || r.Identity == "" || r.KnownHosts == "" {
		return nil, errors.New("invalid SSH target")
	}
	return []string{"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=" + r.KnownHosts, "-o", "ConnectTimeout=5", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2", "-i", r.Identity}, nil
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
func (r Remote) Upload(ctx context.Context, remotePath string, data io.Reader) error {
	args, e := r.args()
	if e != nil {
		return e
	}
	args = append(args, "root@"+r.Host, "umask 077; cat > "+shellSingleQuote(remotePath))
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Stdin = data
	if e = cmd.Run(); e != nil {
		return errors.New("remote upload failed")
	}
	return nil
}

// ReverseTunnel exposes only the primary's loopback PostgreSQL port on the replica's loopback.
func (r Remote) ReverseTunnel(ctx context.Context, primaryPort int) error {
	args, e := r.args()
	if e != nil {
		return e
	}
	args = append(args, "-o", "ExitOnForwardFailure=yes", "-N", "-R", net.JoinHostPort("127.0.0.1", "15432")+":127.0.0.1:"+strconv.Itoa(primaryPort), "root@"+r.Host)
	if e = exec.CommandContext(ctx, "ssh", args...).Run(); e != nil {
		return errors.New("replication SSH tunnel stopped")
	}
	return nil
}
