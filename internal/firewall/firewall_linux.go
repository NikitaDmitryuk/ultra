//go:build linux

package firewall

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type linuxMgr struct{}

func newManager() Manager { return linuxMgr{} }

func (linuxMgr) OpenPort(ctx context.Context, port int) error {
	if port <= 0 || port > 65535 {
		return errors.New("firewall: invalid port")
	}
	ps := strconv.Itoa(port)
	if hasUFW() && ufwActive(ctx) {
		out, err := exec.CommandContext(ctx, "ufw", "allow", ps+"/tcp").CombinedOutput()
		if err != nil && !bytes.Contains(bytes.ToLower(out), []byte("exists")) && !bytes.Contains(bytes.ToLower(out), []byte("skipping")) {
			return err
		}
		return nil
	}
	chk := exec.CommandContext(ctx, "iptables", "-C", "INPUT", "-p", "tcp", "--dport", ps, "-j", "ACCEPT")
	if err := chk.Run(); err == nil {
		return nil
	}
	add := exec.CommandContext(ctx, "iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", ps, "-j", "ACCEPT")
	if out, err := add.CombinedOutput(); err != nil {
		return errors.New("iptables: " + strings.TrimSpace(string(out)))
	}
	_ = tryPersistIPTables(ctx)
	return nil
}

func (linuxMgr) ClosePort(ctx context.Context, port int) error {
	if port <= 0 || port > 65535 {
		return errors.New("firewall: invalid port")
	}
	ps := strconv.Itoa(port)
	if hasUFW() && ufwActive(ctx) {
		_ = exec.CommandContext(ctx, "ufw", "delete", "allow", ps+"/tcp").Run()
		return nil
	}
	del := exec.CommandContext(ctx, "iptables", "-D", "INPUT", "-p", "tcp", "--dport", ps, "-j", "ACCEPT")
	_ = del.Run()
	_ = tryPersistIPTables(ctx)
	return nil
}

func hasUFW() bool {
	_, err := exec.LookPath("ufw")
	return err == nil
}

func ufwActive(ctx context.Context) bool {
	out, err := exec.CommandContext(ctx, "ufw", "status").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "active")
}

func tryPersistIPTables(ctx context.Context) error {
	const rulesFile = "/etc/iptables/rules.v4"
	if _, err := os.Stat(rulesFile); err != nil {
		return nil
	}
	save := exec.CommandContext(ctx, "sh", "-c", "iptables-save > "+rulesFile)
	return save.Run()
}
