package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	ansibleassets "github.com/NikitaDmitryuk/ultra/deploy/ansible"
)

const managedTunnelState = "var/lib/ultra-tunnel-tls"

// Private evidence is produced by the fixed Ansible fence module after it has
// drained managed renewal and validated the certificate/renewal closure. The
// native transaction independently binds it to this exact runtime generation.
type managedTunnelJournal struct {
	Version     int    `json:"version"`
	Binding     string `json:"binding"`
	State       string `json:"state"`
	RequestJSON string `json:"request_json"`
	HookSHA     string `json:"hook_sha256"`
	Request     struct {
		Transaction       string `json:"transaction"`
		Domain            string `json:"domain"`
		RuntimeRequestSHA string `json:"runtime_request_sha256"`
		ReleaseSHA        string `json:"release_sha256"`
	} `json:"request"`
}

func (s runtimeHostStore) managedTunnelAuthority(r runtimeHostRequest) error {
	_, err := s.managedTunnelAuthorityState(r, false)
	return err
}

func (s runtimeHostStore) managedTunnelAuthorityState(r runtimeHostRequest, allowMissing bool) (bool, error) {
	if r.Features.MainExitDomain == "" || r.Role != "exit" {
		return false, nil
	}
	fail := runtimeHostError("managed_tunnel_preservation_unverified")
	journal, err := s.image(s.path(managedTunnelState + "/journal.json"))
	if err != nil || !journal.Exists || journal.UID != uint32(os.Geteuid()) || journal.Mode != 0600 {
		return false, fail
	}
	var evidence managedTunnelJournal
	if json.Unmarshal(journal.Data, &evidence) != nil || evidence.Version != 1 || evidence.State != "frozen" ||
		!runtimeHostValidDigest(evidence.Binding) || !runtimeHostValidDigest(evidence.Request.ReleaseSHA) ||
		evidence.Request.Transaction != r.Transaction || evidence.Request.Domain != r.Features.MainExitDomain ||
		evidence.Request.RuntimeRequestSHA != runtimeHostDigest(r) {
		return false, fail
	}
	expectedHook, hookErr := managedTunnelHookSHA(r.Features.MainExitDomain)
	originalRequest := managedTunnelJournal{}.Request
	if hookErr != nil || evidence.HookSHA != expectedHook ||
		evidence.Binding != managedTunnelBinding(evidence.RequestJSON, evidence.HookSHA) ||
		json.Unmarshal([]byte(evidence.RequestJSON), &originalRequest) != nil ||
		originalRequest != evidence.Request {
		return false, fail
	}
	marker, err := s.image(s.path(managedTunnelState + "/blocked"))
	if err != nil || !marker.Exists || marker.UID != uint32(os.Geteuid()) || marker.Mode != 0600 ||
		string(marker.Data) != evidence.Binding {
		return false, fail
	}
	for _, name := range []string{"certbot.service", "certbot.timer"} {
		path := s.path(filepath.Join("etc/systemd/system", name))
		if s.trustedParent(path) != nil {
			return false, fail
		}
		info, statErr := os.Lstat(path)
		if statErr != nil || info.Mode()&os.ModeSymlink == 0 {
			return false, fail
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		target, linkErr := os.Readlink(path)
		if !ok || owner.Uid != uint32(os.Geteuid()) || linkErr != nil || target != "/dev/null" {
			return false, fail
		}
	}
	checkpoint, err := s.image(s.path(managedTunnelState + "/preservation-" + evidence.Binding + ".json"))
	if err != nil || !checkpoint.Exists || checkpoint.UID != uint32(os.Geteuid()) || checkpoint.Mode != 0600 {
		return false, fail
	}
	var preserved struct {
		Version int    `json:"version"`
		Binding string `json:"binding"`
		Closure struct {
			Images map[string]struct {
				Data []byte `json:"data"`
				Mode uint32 `json:"mode"`
				UID  uint32 `json:"uid"`
				GID  uint32 `json:"gid"`
			} `json:"images"`
		} `json:"closure"`
	}
	if json.Unmarshal(checkpoint.Data, &preserved) != nil || preserved.Version != 1 || preserved.Binding != evidence.Binding {
		return false, fail
	}
	missing := false
	for _, key := range []string{"/etc/ultra-relay/fullchain.pem", "/etc/ultra-relay/privkey.pem", "/etc/letsencrypt/renewal-hooks/deploy/ultra-tunnel"} {
		mode := uint32(0600)
		if strings.HasSuffix(key, "/ultra-tunnel") {
			mode = 0700
		}
		before, found := preserved.Closure.Images[key]
		current, readErr := s.image(s.path(key))
		if found && before.Mode == mode && readErr == nil && !current.Exists && allowMissing && mode == 0600 {
			missing = true
			continue
		}
		if !found || readErr != nil || before.Mode != mode || !runtimeHostImagesEqual(current,
			runtimeHostImage{true, before.Data, before.Mode, before.UID, before.GID}) {
			return false, fail
		}
	}
	return missing, nil
}

// The marker excludes renewal across separate Ansible invocations. Both locks
// also exclude simultaneous release and manual invocations of the known hook
// while this native runtime command checks and changes its exact images.
func (s runtimeHostStore) withManagedTunnelRuntime(
	r runtimeHostRequest,
	allowMissing bool,
	fn func() (runtimeProbeResult, error),
) (runtimeProbeResult, error) {
	if r.Features.MainExitDomain == "" || r.Role != "exit" {
		return fn()
	}
	var descriptors []int
	defer func() {
		for i := len(descriptors) - 1; i >= 0; i-- {
			_ = syscall.Close(descriptors[i])
		}
	}()
	for _, name := range []string{"control.lock", "pair.lock"} {
		path := s.path(filepath.Join(managedTunnelState, name))
		if s.trustedParent(path) != nil {
			return runtimeProbeResult{}, runtimeHostError("managed_tunnel_lock_untrusted")
		}
		fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return runtimeProbeResult{}, runtimeHostError("managed_tunnel_lock_untrusted")
		}
		descriptors = append(descriptors, fd)
		var info syscall.Stat_t
		if syscall.Fstat(fd, &info) != nil || info.Uid != uint32(os.Geteuid()) || info.Mode&0077 != 0 ||
			info.Mode&syscall.S_IFMT != syscall.S_IFREG || info.Nlink != 1 || syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
			return runtimeProbeResult{}, runtimeHostError("managed_tunnel_busy")
		}
	}
	missing, err := s.managedTunnelAuthorityState(r, allowMissing)
	if err != nil {
		return runtimeProbeResult{}, err
	}
	result, err := fn()
	result.ManagedTLSRestorable = missing
	return result, err
}

func managedTunnelBinding(requestJSON, hookSHA string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(requestJSON+"\n"+hookSHA)))
}

func managedTunnelHookSHA(domain string) (string, error) {
	raw, err := ansibleassets.Bundle.ReadFile("roles/tunnel_certificate/templates/deploy-certificate.sh.j2")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.ReplaceAll(string(raw), "{{ ultra_tunnel_domain }}", domain)))), nil
}
