package main

import (
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"strings"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

type runtimeProbeInput struct {
	DomainTransaction  string             `json:"domain_transaction,omitempty"`
	Action             string             `json:"action,omitempty"`
	BotActive          bool               `json:"bot_active,omitempty"`
	Request            runtimeHostRequest `json:"request"`
	SubscriptionDomain string             `json:"subscription_domain,omitempty"`
	VPNDomain          string             `json:"vpn_domain,omitempty"`
	BotDomain          string             `json:"bot_domain,omitempty"`
}

type runtimeProbeResult struct {
	Bound                bool                                `json:"bound"`
	Status               string                              `json:"status,omitempty"`
	BotActive            bool                                `json:"bot_active,omitempty"`
	Verified             bool                                `json:"verified"`
	RuntimeChanged       bool                                `json:"runtime_changed"`
	DomainChanged        bool                                `json:"domain_changed"`
	EffectsReady         bool                                `json:"effects_ready"`
	ManagedTLSReady      bool                                `json:"managed_tls_ready,omitempty"`
	ManagedTLSRestorable bool                                `json:"managed_tls_restorable,omitempty"`
	EffectsPlan          *runtimeTransitionPlan              `json:"effects_plan,omitempty"`
	Transitions          []installplan.RuntimeTransitionKind `json:"transitions"`
}

func inspectRuntimeHost(s runtimeHostStore, in runtimeProbeInput) (runtimeProbeResult, error) {
	var result runtimeProbeResult
	_, err := s.locked(func() (runtimeHostResult, error) {
		var inspectErr error
		result, inspectErr = inspectRuntimeHostLocked(s, in)
		return runtimeHostResult{}, inspectErr
	})
	return result, err
}

func runtimeHostTransport(s runtimeHostStore, in runtimeProbeInput) (runtimeProbeResult, error) {
	result, err := s.withManagedTunnelRuntime(in.Request, in.Action == "status", func() (runtimeProbeResult, error) {
		return runtimeHostTransportFenced(s, in)
	})
	if err == nil && !result.ManagedTLSRestorable && in.Request.Features.MainExitDomain != "" && in.Request.Role == config.RoleExit {
		result.ManagedTLSReady = true
	}
	return result, err
}

func runtimeHostTransportFenced(s runtimeHostStore, in runtimeProbeInput) (runtimeProbeResult, error) {
	lockPath := s.path("etc/ultra-recovery/runtime-transport.lock")
	if s.trustedParent(lockPath) != nil {
		return runtimeProbeResult{}, runtimeHostError("file_untrusted")
	}
	fd, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return runtimeProbeResult{}, runtimeHostError("lock_failed")
	}
	defer syscall.Close(fd) //nolint:errcheck
	var stat syscall.Stat_t
	if syscall.Fstat(fd, &stat) != nil || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0077 != 0 ||
		stat.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		stat.Nlink != 1 ||
		syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return runtimeProbeResult{}, runtimeHostError("lock_failed")
	}
	defer syscall.Flock(fd, syscall.LOCK_UN) //nolint:errcheck
	return runtimeHostTransportLocked(s, in)
}

func runtimeHostTransportLocked(s runtimeHostStore, in runtimeProbeInput) (runtimeProbeResult, error) {
	id := in.Request.Transaction
	path, err := s.journalPath(id)
	if err != nil {
		return runtimeProbeResult{}, err
	}
	bound := in
	bound.Action = ""
	bound.BotActive = false
	digest := runtimeHostDigest(bound)
	bindingPath := strings.TrimSuffix(path, ".json") + ".transport.json"
	if in.Action == "rollback" || in.Action == "status" {
		if _, stateErr := os.Lstat(s.path(runtimeHostStateDir)); os.IsNotExist(stateErr) {
			return runtimeProbeResult{Verified: true, Status: "rolled_back"}, nil
		} else if stateErr != nil {
			return runtimeProbeResult{}, runtimeHostError("file_untrusted")
		}
	}
	if in.Action == "prepare" {
		if _, err = os.Lstat(s.path(runtimeHostStateDir)); os.IsNotExist(err) {
			if s.trustedParent(path) != nil { // Parent does not exist yet; validate its existing ancestor.
				if s.trustedParent(s.path(runtimeHostIdentityFile)) != nil {
					return runtimeProbeResult{}, runtimeHostError("file_untrusted")
				}
			}
			if os.Mkdir(s.path(runtimeHostStateDir), 0700) != nil {
				return runtimeProbeResult{}, runtimeHostError("write_failed")
			}
		} else if err != nil {
			return runtimeProbeResult{}, runtimeHostError("file_untrusted")
		}
	}
	binding, err := s.image(bindingPath)
	if err != nil {
		return runtimeProbeResult{}, err
	}
	journal, err := s.image(path)
	if err != nil {
		return runtimeProbeResult{}, err
	}
	proof := struct {
		Digest      string                 `json:"digest"`
		BotActive   bool                   `json:"bot_active"`
		EffectsPlan *runtimeTransitionPlan `json:"effects_plan,omitempty"`
	}{digest, in.BotActive, nil}
	if binding.Exists {
		if binding.UID != uint32(os.Geteuid()) || binding.Mode != 0600 || json.Unmarshal(binding.Data, &proof) != nil ||
			proof.Digest != digest {
			return runtimeProbeResult{}, runtimeHostError("request_changed")
		}
	} else if (in.Action == "rollback" || in.Action == "status") && !journal.Exists {
		return runtimeProbeResult{Verified: true, Status: "rolled_back"}, nil
	} else if in.Action != "prepare" || journal.Exists {
		return runtimeProbeResult{}, runtimeHostError("request_unbound")
	}
	if in.Action == "status" {
		if journal.Exists {
			var saved runtimeHostJournal
			if journal.UID != uint32(os.Geteuid()) || journal.Mode != 0600 || json.Unmarshal(journal.Data, &saved) != nil ||
				saved.Version != 1 ||
				saved.Transaction != id ||
				(saved.State != "prepared" && saved.State != "applied" && saved.State != "rolled_back") {
				return runtimeProbeResult{}, runtimeHostError("journal_invalid")
			}
		}
		return runtimeProbeResult{
			Verified:    true,
			Bound:       journal.Exists,
			Status:      "checked",
			BotActive:   proof.BotActive,
			EffectsPlan: proof.EffectsPlan,
		}, nil
	}
	if in.Action == "prepare" {
		if journal.Exists {
			var saved runtimeHostJournal
			if json.Unmarshal(journal.Data, &saved) != nil || saved.Version != 1 || saved.Transaction != id ||
				(saved.State != "prepared" && saved.State != "applied") {
				return runtimeProbeResult{}, runtimeHostError("journal_invalid")
			}
			return runtimeProbeResult{
				Verified:    true,
				Bound:       true,
				Status:      saved.State,
				BotActive:   proof.BotActive,
				EffectsPlan: proof.EffectsPlan,
			}, nil
		}
		probe, probeErr := inspectRuntimeHost(s, in)
		if probeErr != nil {
			return runtimeProbeResult{}, probeErr
		}
		if (probe.DomainChanged && !s.authorizedDomainTransition(in)) ||
			!s.authorizedRuntimeTransitions(in, probe.Transitions, probe.EffectsPlan) {
			return runtimeProbeResult{}, runtimeHostError("unsupported_transition")
		}
		if !binding.Exists {
			proof.EffectsPlan = probe.EffectsPlan
			raw, _ := json.Marshal(proof)
			if err = s.persist(bindingPath, runtimeHostImage{true, raw, 0600, uint32(os.Geteuid()), uint32(os.Getegid())}); err != nil {
				return runtimeProbeResult{}, err
			}
		}
		result, prepareErr := s.prepare(in.Request)
		return runtimeProbeResult{
			Verified:    prepareErr == nil,
			Bound:       prepareErr == nil,
			Status:      result.Status,
			BotActive:   proof.BotActive,
			EffectsPlan: proof.EffectsPlan,
		}, prepareErr
	}
	if in.Action == "rollback" && !journal.Exists {
		return runtimeProbeResult{Verified: true, Status: "rolled_back", BotActive: proof.BotActive, EffectsPlan: proof.EffectsPlan}, nil
	}
	result, transitionErr := s.transition(id, in.Action == "rollback")
	return runtimeProbeResult{
		Verified:    transitionErr == nil,
		Bound:       true,
		Status:      result.Status,
		BotActive:   proof.BotActive,
		EffectsPlan: proof.EffectsPlan,
	}, transitionErr
}

func inspectRuntimeHostLocked(s runtimeHostStore, in runtimeProbeInput) (runtimeProbeResult, error) {
	r := in.Request
	if in.DomainTransaction != "" && !s.authorizedDomainTransition(in) {
		return runtimeProbeResult{}, runtimeHostError("domain_transaction_unbound")
	}
	if _, err := s.journalPath(r.Transaction); err != nil {
		return runtimeProbeResult{}, err
	}
	desired, err := runtimeHostDesiredIdentity(r)
	if err != nil {
		return runtimeProbeResult{}, err
	}
	// A retained attestation does not replace this invocation's trusted DB proof.
	if r.Role == config.RoleExit {
		if _, proofErr := s.liveExitAttestation(r); proofErr != nil {
			return runtimeProbeResult{}, proofErr
		}
	}
	specImage, err := s.image(s.path(runtimeHostFiles[0]))
	if err != nil || !specImage.Exists {
		return runtimeProbeResult{}, runtimeHostError("file_unavailable")
	}
	if _, err := runtimeHostInstalledIdentity(specImage.Data); err != nil {
		return runtimeProbeResult{}, err
	}
	att, err := s.image(s.path(runtimeHostIdentityFile))
	if err != nil {
		return runtimeProbeResult{}, err
	}
	var baseline runtimeHostAttestation
	if att.Exists {
		if att.UID != uint32(os.Geteuid()) || att.Mode != 0600 || json.Unmarshal(att.Data, &baseline) != nil {
			return runtimeProbeResult{}, runtimeHostError("identity_uncertain")
		}
	} else if r.Role == config.RoleBridge {
		baseline, err = s.liveBridgeAttestation(r)
	} else {
		baseline, err = s.liveExitAttestation(r)
	}
	if err != nil {
		return runtimeProbeResult{}, err
	}
	if baseline.DesiredIdentity != desired || !runtimeHostInstalledIdentityMatches(baseline.RuntimeIdentity, specImage.Data) {
		return runtimeProbeResult{}, runtimeHostError("migration_required")
	}
	p := &installplan.InstallPlan{
		SchemaVersion: 1,
		SourceValues:  map[string]string{},
		Bridge:        r.Bridge,
		Database:      r.Database,
		Features:      r.Features,
		Bot:           installplan.BotConfig{Enabled: r.BotEnabled},
	}
	p.Bridge.ReuseSpec = true
	for _, ex := range r.Exits {
		p.Exits = append(p.Exits, installplan.ExitNode{Name: ex.Name, SSHHost: ex.SSHHost, DialAddr: ex.DialAddr, Port: ex.Port})
	}
	project := installplan.ProjectLocalRuntime
	if r.Features.MainExitDomain != "" {
		project = installplan.ProjectLocalManagedTunnelRuntime
	}
	projection, err := project(p, specImage.Data, r.Role, r.Node)
	if err != nil {
		return runtimeProbeResult{}, runtimeHostError("projection_failed")
	}
	var before, after any
	if json.Unmarshal(specImage.Data, &before) != nil || json.Unmarshal(projection.SpecJSON, &after) != nil {
		return runtimeProbeResult{}, runtimeHostError("projection_failed")
	}
	result := runtimeProbeResult{
		Verified:       true,
		RuntimeChanged: !reflect.DeepEqual(before, after),
		Transitions:    []installplan.RuntimeTransitionKind{},
	}
	environment, err := s.image(s.path(runtimeHostFiles[1]))
	if err != nil {
		return runtimeProbeResult{}, err
	}
	logMatches, logCount := false, 0
	for _, line := range strings.Split(string(environment.Data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(key) == "ULTRA_RELAY_LOG_LEVEL" {
			logCount++
			logMatches = value == r.Features.LogLevel
		}
	}
	if logCount != 1 || !logMatches {
		result.RuntimeChanged = true
	}
	seen := map[installplan.RuntimeTransitionKind]bool{}
	for _, transition := range projection.Transitions {
		if !seen[transition.Kind] {
			result.Transitions = append(result.Transitions, transition.Kind)
			seen[transition.Kind] = true
		}
	}
	result.EffectsPlan, err = buildRuntimeTransitionPlan(in, projection.SpecJSON, result.Transitions, specImage.Data)
	if err != nil {
		return runtimeProbeResult{}, err
	}
	if r.Role == config.RoleBridge {
		var spec config.Spec
		if json.Unmarshal(specImage.Data, &spec) != nil {
			return runtimeProbeResult{}, runtimeHostError("projection_failed")
		}
		if r.Bridge.PublicHost != spec.PublicHost {
			result.DomainChanged = true
		}
		if in.VPNDomain != "" && (spec.PrimaryXHTTP == nil || spec.PrimaryXHTTP.ServerName != in.VPNDomain) {
			result.DomainChanged = true
		}
		// These are managed public nginx files, not the bot environment or .env.
		if in.SubscriptionDomain != "" || in.BotDomain != "" {
			image, readErr := s.image(s.path("etc/nginx/conf.d/ultra-subscription.conf"))
			if readErr != nil || !image.Exists || image.UID != uint32(os.Geteuid()) {
				return runtimeProbeResult{}, runtimeHostError("domain_identity_uncertain")
			}
			if !runtimeProbeDirective(image.Data, "server_name", in.SubscriptionDomain) ||
				!runtimeProbeDirective(image.Data, "proxy_ssl_name", in.BotDomain) {
				result.DomainChanged = true
			}
		}
	}
	return result, nil
}

func runtimeProbeDirective(raw []byte, directive, desired string) bool {
	if desired == "" || strings.ContainsAny(desired, " \t\r\n;{}") {
		return false
	}
	pattern := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(directive) + `\s+([^;\s]+)\s*;\s*$`)
	matches := pattern.FindAllSubmatch(raw, -1)
	if len(matches) == 0 {
		return false
	}
	for _, match := range matches {
		if string(match[1]) != desired {
			return false
		}
	}
	return true
}

func (s runtimeHostStore) authorizedDomainTransition(in runtimeProbeInput) bool {
	if in.Request.Role != config.RoleBridge || !runtimeHostValidDigest(in.DomainTransaction) {
		return false
	}
	image, err := s.image(s.path("var/lib/ultra-ingress/upgrade-" + in.DomainTransaction + "/binding.json"))
	if err != nil || !image.Exists || image.Mode != 0600 || image.UID != uint32(os.Geteuid()) {
		return false
	}
	var binding struct {
		Version     int                   `json:"version"`
		Transaction string                `json:"transaction"`
		Desired     map[string]string     `json:"desired"`
		Evidence    upgradeDomainEvidence `json:"evidence"`
	}
	if json.Unmarshal(image.Data, &binding) != nil || binding.Version != 1 || binding.Transaction != in.DomainTransaction ||
		!binding.Evidence.Verified {
		return false
	}
	return binding.Desired["subscription"] == in.SubscriptionDomain && binding.Desired["vpn"] == in.VPNDomain &&
		binding.Desired["backend"] == in.BotDomain &&
		binding.Desired["public_host"] == in.Request.Bridge.PublicHost
}
