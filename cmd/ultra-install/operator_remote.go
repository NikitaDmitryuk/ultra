package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
	"github.com/NikitaDmitryuk/ultra/internal/operatorssh"
)

func quoteRetainedArgs(args []string) []string {
	out := make([]string, len(args))
	for n, a := range args {
		out[n] = shellQuote(a)
	}
	return out
}

func retainedSSH(p *installplan.InstallPlan, address, key string, proxy, destination bool, profiles ...string) []string {
	profile := "probe"
	if len(profiles) > 0 && profiles[0] == "mutate" {
		profile = "mutate"
	}
	args := []string{
		"ssh", "-F", "/dev/null", "-T",
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
		"-o", "GlobalKnownHostsFile=/dev/null",
	}
	args = append(args, operatorssh.DefaultPolicy.Options(profile)...)
	args = append(args, "-o", "UserKnownHostsFile="+p.Automation.KnownHostsFile, "-i", key)
	if proxy {
		args = append(args, "-o", "ProxyCommand="+retainedProxyCommand(p, profile))
	}
	if destination {
		args = append(args, "root@"+address)
	}
	return args
}

func retainedProxyCommand(p *installplan.InstallPlan, profiles ...string) string {
	profile := "probe"
	if len(profiles) > 0 && profiles[0] == "mutate" {
		profile = "mutate"
	}
	jump := retainedSSH(p, p.Bridge.SSHHost, p.BridgeSSHIdentity(), false, false, profile)
	jump = append(jump, "-W", "%h:%p", "root@"+p.Bridge.SSHHost)
	return strings.Join(quoteRetainedArgs(jump), " ")
}

func retainedRemote(
	ctx context.Context,
	p *installplan.InstallPlan,
	address, key string,
	proxy bool,
	program string,
	parameters []string,
) ([]byte, error) {
	return retainedRemoteOperation(ctx, p, address, key, proxy, program, parameters, false)
}

func retainedMutation(
	ctx context.Context,
	p *installplan.InstallPlan,
	address, key string,
	proxy bool,
	program string,
	parameters []string,
) ([]byte, error) {
	return retainedRemoteOperation(ctx, p, address, key, proxy, program, parameters, true)
}

func retainedRemoteOperation(
	ctx context.Context,
	p *installplan.InstallPlan,
	address, key string,
	proxy bool,
	program string,
	parameters []string,
	mutate bool,
) ([]byte, error) {
	profile := "probe"
	if mutate {
		profile = "mutate"
	}
	args := retainedSSH(p, address, key, proxy, true, profile)
	remote := append([]string{"python3", "-"}, parameters...)
	args = append(args, strings.Join(quoteRetainedArgs(remote), " "))
	role := "exit"
	if proxy {
		role = "database"
	} else if address == p.Bridge.SSHHost {
		role = "bridge"
	}
	run := runRetainedReadOnlySSH
	if mutate {
		run = runRetainedMutationSSH
	}
	out, err := run(ctx, role, args, []byte(program), func(line string) { fmt.Fprintln(os.Stderr, line) })
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("retained_primary_remote_cancelled: %w", ctx.Err())
		}
		if retainedReadOnlyFailureKind(err) == "transport_exhausted" {
			return nil, fmt.Errorf("retained_primary_remote_transport_failed: role=%s: %w", role, err)
		}
		return nil, fmt.Errorf("retained_primary_remote_check_failed: role=%s: %w", role, err)
	}
	return out, nil
}

func retainedExistingDatabaseCredentials(p *installplan.InstallPlan) (string, error) {
	path := p.Secrets.DatabaseCredentialsFile
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("retained_primary_existing_database_credentials_required")
	}
	if _, err := readRebuildInput(path, true); err != nil {
		return "", errors.New("retained_primary_existing_database_credentials_invalid")
	}
	dsn, err := installplan.ReadDatabaseCredentials(path)
	if err != nil {
		return "", errors.New("retained_primary_existing_database_credentials_invalid")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme != "postgres" || u.User == nil || u.Hostname() != "127.0.0.1" || u.Port() != "25432" ||
		strings.TrimPrefix(u.Path, "/") != p.Database.Name ||
		u.User.Username() != p.Database.User {
		return "", errors.New("retained_primary_existing_database_credentials_identity_mismatch")
	}
	if password, ok := u.User.Password(); !ok || password == "" {
		return "", errors.New("retained_primary_existing_database_credentials_required")
	}
	return dsn, nil
}
