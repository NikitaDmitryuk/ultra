package cloudinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/install"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/NikitaDmitryuk/ultra/internal/proxy"
)

type ExitConfigurer interface {
	Ready(context.Context) error
	ConfigureExit(context.Context, string, string, deployansible.ExitRequest) (deployansible.Result, error)
}

type Provisioner struct {
	Configurer                           ExitConfigurer
	API                                  *cloud.Vultr
	DB                                   *db.DB
	Bridge                               *config.Spec
	Exits                                *exits.Manager
	Routes                               *db.RouteRepo
	Identity, StateDir, BridgeIP, Binary string
	Apply                                func(context.Context) error
	Refresh                              func(context.Context) error
}

func (p *Provisioner) port() int {
	if p.Bridge.Exit.Port > 0 {
		return p.Bridge.Exit.Port
	}
	return p.Bridge.VLESSPort
}
func (p *Provisioner) remote(op *cloud.Operation, instance cloud.Instance) (install.Remote, error) {
	if net.ParseIP(instance.IP) == nil {
		return install.Remote{}, errors.New("instance address unavailable")
	}
	dir := filepath.Join(p.StateDir, op.ID)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return install.Remote{}, e
	}
	return install.Remote{
		Host:             instance.IP,
		Identity:         p.Identity,
		KnownHosts:       filepath.Join(dir, "known_hosts"),
		RequireKnownHost: op.Reinstall,
	}, nil
}
func (p *Provisioner) Prepare(ctx context.Context, op *cloud.Operation) (cloud.CreateRequest, error) {
	if p.Configurer == nil {
		return cloud.CreateRequest{}, errors.New("ansible controller required")
	}
	if e := p.Configurer.Ready(ctx); e != nil {
		return cloud.CreateRequest{}, e
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || net.ParseIP(p.BridgeIP).To4() == nil {
		return cloud.CreateRequest{}, errors.New("provisioning host must be Linux amd64 with configured public IPv4")
	}
	dir := filepath.Join(p.StateDir, op.ID)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return cloud.CreateRequest{}, e
	}
	pinned := filepath.Join(dir, "ultra-relay")
	if _, e := os.Stat(pinned); os.IsNotExist(e) {
		source, e := os.Open(p.Binary)
		if e != nil {
			return cloud.CreateRequest{}, e
		}
		defer source.Close() //nolint:errcheck
		dest, e := os.OpenFile(pinned+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0700)
		if e != nil {
			return cloud.CreateRequest{}, e
		}
		_, e = io.Copy(dest, source)
		closeErr := dest.Close()
		if e != nil {
			return cloud.CreateRequest{}, e
		}
		if closeErr != nil {
			return cloud.CreateRequest{}, closeErr
		}
		if e = os.Rename(pinned+".tmp", pinned); e != nil {
			return cloud.CreateRequest{}, e
		}
	}
	key, e := os.ReadFile(p.Identity + ".pub")
	if e != nil {
		return cloud.CreateRequest{}, errors.New("provisioning SSH key unavailable")
	}
	keyID, e := p.API.EnsureSSHKey(ctx, "ultra-provisioner", string(key))
	if e != nil {
		return cloud.CreateRequest{}, e
	}
	firewall, e := p.API.EnsureFirewall(ctx, op.ID, p.BridgeIP, p.port())
	if e != nil {
		return cloud.CreateRequest{}, e
	}
	op.FirewallID = firewall
	osID, e := p.API.Ubuntu2404(ctx)
	if e != nil {
		return cloud.CreateRequest{}, e
	}
	return cloud.CreateRequest{OSID: osID, SSHKeys: []string{keyID}, Firewall: firewall}, nil
}
func (p *Provisioner) node(ctx context.Context, op *cloud.Operation, instance cloud.Instance) (exits.Node, error) {
	// The operation UUID also identifies the staged exit, so a lost checkpoint cannot duplicate it.
	repo := db.NewExitNodeRepo(p.DB)
	n, e := repo.Get(ctx, op.ID)
	if e == nil {
		op.ExitID = n.ID
		return n, nil
	}
	if !errors.Is(e, db.ErrExitNotFound) {
		return n, e
	}
	disabled := false
	n, e = repo.Add(
		ctx,
		exits.AddParams{
			ID:          op.ID,
			Name:        "vultr-" + op.Offer.Region.ID,
			Address:     instance.IP,
			Port:        p.port(),
			Priority:    200,
			Enabled:     &disabled,
			CountryCode: op.Offer.Region.Country,
			CountryName: op.Offer.Region.Country,
			City:        op.Offer.Region.City,
			DisplayName: op.Offer.Region.City + ", " + op.Offer.Region.Country,
		},
	)
	if e == nil {
		op.ExitID = n.ID
	}
	return n, e
}

func (p *Provisioner) exitSpec(node exits.Node) config.Spec {
	spec := config.Spec{
		SchemaVersion: config.CurrentSpecSchemaVersion, Role: config.RoleExit,
		MimicPreset: p.Bridge.MimicPreset, ListenAddress: "0.0.0.0", VLESSPort: node.Port,
		SplithttpHost: p.Bridge.SplithttpHost, SplithttpPath: p.Bridge.SplithttpPath,
		SplitHTTPTLS: p.Bridge.SplitHTTPTLS, TunnelTransport: p.Bridge.TunnelTransport,
		// The cloud worker provisions an IP exit with a pinned certificate;
		// the bridge's static ACME domain is not owned by this instance.
		TunnelTLSProvision: config.TunnelTLSSelfSigned,
		Exit:               config.ExitTunnelSpec{TunnelUUID: node.TunnelUUID},
		ExitCertPaths:      config.CertPaths{CertFile: "/etc/ultra-relay/fullchain.pem", KeyFile: "/etc/ultra-relay/privkey.pem"},
	}
	if p.Bridge.XrayWire != nil {
		wire := *p.Bridge.XrayWire
		wire.SniffingDestOverride = append([]string(nil), wire.SniffingDestOverride...)
		spec.XrayWire = &wire
	}
	if p.Bridge.AntiCensor != nil {
		anti := *p.Bridge.AntiCensor
		anti.WARPProxy = false
		anti.PublicXHTTPPort = 0
		spec.AntiCensor = &anti
	}
	return spec
}

var errReinstallSnapshotUnavailable = errors.New("reserved reinstall attempt snapshot unavailable")

// reinstallInputs commits the whole attempt with one rename. A retry never reads
// live binary/configuration files once its attempt directory has been published.
func (p *Provisioner) reinstallInputs(
	op *cloud.Operation,
	request deployansible.ExitRequest,
) (string, deployansible.ExitRequest, error) {
	dir := filepath.Join(p.StateDir, op.ID, fmt.Sprintf("install-attempt-%d", op.InstallAttempt))
	binary := filepath.Join(dir, "ultra-relay")
	load := func() (string, deployansible.ExitRequest, error) {
		var saved deployansible.ExitRequest
		raw, err := os.ReadFile(filepath.Join(dir, "request.json"))
		if err != nil {
			return "", saved, err
		}
		if err = json.Unmarshal(raw, &saved); err != nil {
			return "", saved, err
		}
		jobID, err := configurationAttemptJobID(op.ID, op.InstallAttempt, binary, saved)
		if err != nil {
			return "", saved, err
		}
		digest, err := os.ReadFile(filepath.Join(dir, "job-id"))
		if err != nil || string(digest) != jobID ||
			(op.ReinstallJobID != "" && op.ReinstallJobID != jobID) {
			return "", saved, errors.New("reinstall attempt inputs changed")
		}
		return binary, saved, nil
	}
	if _, err := os.Stat(dir); err == nil {
		return load()
	} else if !os.IsNotExist(err) {
		return "", request, err
	}
	// A controller might still own a receipt created by an older worker. Never
	// replace its inputs with current desired state.
	if op.ReinstallJobID != "" {
		return "", request, errReinstallSnapshotUnavailable
	}
	tmp, err := os.MkdirTemp(filepath.Dir(dir), ".install-attempt-")
	if err != nil {
		return "", request, err
	}
	defer os.RemoveAll(tmp) //nolint:errcheck
	saved := request
	saved.Identity = filepath.Join(dir, "identity")
	saved.KnownHosts = filepath.Join(dir, "known_hosts")
	for _, input := range []struct {
		source, name string
		mode         os.FileMode
	}{
		{p.Binary, "ultra-relay", 0700},
		{request.Identity, "identity", 0600},
		{request.KnownHosts, "known_hosts", 0600},
	} {
		if err := copyAttemptInput(input.source, filepath.Join(tmp, input.name), input.mode); err != nil {
			return "", request, err
		}
	}
	raw, err := json.Marshal(saved)
	if err != nil {
		return "", request, err
	}
	if err = os.WriteFile(filepath.Join(tmp, "request.json"), raw, 0600); err != nil {
		return "", request, err
	}
	// Hash the staged copies while retaining the final paths in the request.
	// Hashing uses paths only in request JSON, and contents for the input files.
	staged := saved
	staged.Identity = filepath.Join(tmp, "identity")
	staged.KnownHosts = filepath.Join(tmp, "known_hosts")
	jobID, err := configurationInputsJobID(op.ID, op.InstallAttempt, filepath.Join(tmp, "ultra-relay"), saved, staged)
	if err != nil {
		return "", request, err
	}
	if err = os.WriteFile(filepath.Join(tmp, "job-id"), []byte(jobID), 0600); err != nil {
		return "", request, err
	}
	if err = os.Rename(tmp, dir); err != nil {
		// A concurrent caller may have committed the same attempt first.
		if _, statErr := os.Stat(dir); statErr != nil {
			return "", request, err
		}
	}
	return load()
}

func copyAttemptInput(source, target string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return errors.New("configuration inputs unavailable")
	}
	defer input.Close() //nolint:errcheck
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	return errors.Join(copyErr, closeErr)
}

func (p *Provisioner) reconcileReinstallFirewall(
	ctx context.Context,
	op *cloud.Operation,
	node exits.Node,
	bridgeIPv4 string,
) error {
	if net.ParseIP(bridgeIPv4).To4() == nil || node.Port < 1 || node.Port > 65535 ||
		op.FirewallID == "" {
		return errors.New("reinstall firewall inputs invalid")
	}
	firewall, err := p.API.EnsureFirewall(ctx, op.ID, bridgeIPv4, node.Port)
	if err != nil {
		return err
	}
	if firewall != op.FirewallID {
		return errors.New("reinstall firewall identity mismatch")
	}
	return nil
}

// The controller owns a durable job and allows Ansible fifteen minutes. The
// caller must leave time to observe that terminal receipt after SSH readiness.
const exitSSHReadyTimeout = 5 * time.Minute
const exitConfigurationTimeout = 16 * time.Minute

func (p *Provisioner) Install(ctx context.Context, op *cloud.Operation, instance cloud.Instance) error {
	c, cancel := context.WithTimeout(ctx, exitSSHReadyTimeout+exitConfigurationTimeout)
	defer cancel()
	remote, e := p.remote(op, instance)
	if e != nil {
		return e
	}
	var node exits.Node
	var request deployansible.ExitRequest
	binary := filepath.Join(p.StateDir, op.ID, "ultra-relay")
	if op.Reinstall {
		node, e = db.NewExitNodeRepo(p.DB).Get(c, op.ExitID)
		if e != nil {
			return e
		}
		if e := validateReinstallTarget(op, node, instance); e != nil {
			return e
		}
		release, err := db.NewExitNodeRepo(p.DB).GuardCloudReinstall(c, op, node, instance)
		if err != nil {
			return err
		}
		defer release()
		request = deployansible.ExitRequest{
			Host: instance.IP, User: "root", Identity: p.Identity, KnownHosts: remote.KnownHosts,
			BridgeIPv4: p.BridgeIP, Spec: p.exitSpec(node),
		}
		binary, request, e = p.reinstallInputs(op, request)
		if e != nil {
			if errors.Is(e, errReinstallSnapshotUnavailable) {
				// Legacy receipts have no immutable inputs to replay. Only terminal
				// proof may release ownership; even then this install must fail so
				// an explicit retry creates a fresh attempt on the existing VPS.
				cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				releaseErr := p.ReleaseReinstall(cleanup, op)
				stop()
				return errors.Join(e, releaseErr)
			}
			return e
		}
		remote.Identity, remote.KnownHosts = request.Identity, request.KnownHosts
		if e = p.reconcileReinstallFirewall(c, op, node, request.BridgeIPv4); e != nil {
			return e
		}
	}
	sshReady, stopSSHReady := context.WithTimeout(c, exitSSHReadyTimeout)
	defer stopSSHReady()
	for {
		if _, e = remote.Run(sshReady, "true"); e == nil {
			break
		}
		select {
		case <-sshReady.Done():
			return sshReady.Err()
		case <-time.After(5 * time.Second):
		}
	}
	stopSSHReady()
	if !op.Reinstall {
		node, e = p.node(c, op, instance)
		if e != nil {
			return e
		}
	}
	if op.Reinstall {
		// Public certificate only; strict SSH checking retains the operation's
		// original host identity before any desired files are installed.
		fingerprint, err := remote.Run(
			c,
			"set -o pipefail\nopenssl x509 -in /etc/ultra-relay/fullchain.pem -outform DER | sha256sum\n",
		)
		if err != nil || len(strings.Fields(string(fingerprint))) != 2 ||
			strings.Fields(string(fingerprint))[0] != node.PinnedPeerCertSHA256 {
			return errors.New("reinstall certificate identity mismatch")
		}
	}
	if !op.Reinstall {
		request = deployansible.ExitRequest{
			Host: instance.IP, User: "root", Identity: p.Identity, KnownHosts: remote.KnownHosts,
			BridgeIPv4: p.BridgeIP, Spec: p.exitSpec(node),
		}
	}
	if e = request.Spec.Validate(); e != nil {
		return errors.New("generated exit spec invalid")
	}
	if p.Configurer == nil {
		return errors.New("ansible controller required")
	}
	if op.Reinstall {
		jobID, err := configurationAttemptJobID(op.ID, op.InstallAttempt, binary, request)
		if err != nil {
			return err
		}
		if err := db.NewExitNodeRepo(p.DB).ReserveCloudReinstall(c, op, jobID, node.Address); err != nil {
			return err
		}
	}
	var result deployansible.Result
	var err error
	if op.Reinstall {
		// Dispatch exactly the durably reserved identity, even if an input file
		// changes between computing its digest and opening submission inputs.
		result, err = p.configureExitJob(c, op.ReinstallJobID, binary, request)
	} else {
		result, err = p.configureExit(c, op, binary, request)
	}
	if op.Reinstall {
		// The controller may keep running after this caller times out. Persisted
		// host ownership survives that timeout; only a terminal receipt clears it.
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		releaseErr := p.ReleaseReinstall(cleanup, op)
		stop()
		if releaseErr != nil {
			return errors.Join(err, releaseErr)
		}
	}
	if err != nil {
		return err
	}
	if op.Reinstall && result.CertPin != node.PinnedPeerCertSHA256 {
		return errors.New("reinstall certificate identity changed")
	}
	if err = p.Routes.SetPin(c, node.ID, result.CertPin); err != nil {
		return err
	}
	return nil
}

func (p *Provisioner) ReleaseReinstall(ctx context.Context, op *cloud.Operation) error {
	return releaseReinstall(ctx, op, p.Configurer, db.NewExitNodeRepo(p.DB).ClearCloudReinstall)
}

func releaseReinstall(
	ctx context.Context,
	op *cloud.Operation,
	configurer ExitConfigurer,
	clear func(context.Context, *cloud.Operation) error,
) error {
	if op.ReinstallTarget == "" {
		return cloud.ErrConflict
	}
	if op.ReinstallJobID == "" {
		return clear(ctx, op)
	}
	reader, ok := configurer.(interface {
		ConfigurationTerminal(context.Context, string) (bool, error)
	})
	if !ok || op.ReinstallJobID == "" {
		return cloud.ErrConflict
	}
	terminal, err := reader.ConfigurationTerminal(ctx, op.ReinstallJobID)
	if err != nil {
		return err
	}
	if !terminal {
		return cloud.ErrConflict
	}
	return clear(ctx, op)
}

func validateReinstallTarget(op *cloud.Operation, node exits.Node, instance cloud.Instance) error {
	pin, err := hex.DecodeString(node.PinnedPeerCertSHA256)
	if op.ID != op.ExitID || node.ID != op.ID || node.Enabled || node.Address != instance.IP || instance.ID != op.InstanceID ||
		net.ParseIP(
			node.Address,
		) == nil || err != nil || len(pin) != sha256.Size || strings.ToLower(node.PinnedPeerCertSHA256) != node.PinnedPeerCertSHA256 {
		return errors.New("reinstall target identity mismatch")
	}
	return nil
}

func (p *Provisioner) configureExit(
	ctx context.Context,
	op *cloud.Operation,
	binary string,
	request deployansible.ExitRequest,
) (deployansible.Result, error) {
	jobID, err := configurationAttemptJobID(op.ID, op.InstallAttempt, binary, request)
	if err != nil {
		return deployansible.Result{}, err
	}
	return p.configureExitJob(ctx, jobID, binary, request)
}

func (p *Provisioner) configureExitJob(
	ctx context.Context,
	jobID, binary string,
	request deployansible.ExitRequest,
) (deployansible.Result, error) {
	c, cancel := context.WithTimeout(ctx, exitConfigurationTimeout)
	defer cancel()
	return p.Configurer.ConfigureExit(c, jobID, binary, request)
}

// Purchase identity stays stable; a changed desired configuration needs a new
// immutable job instead of reusing a receipt for the former bridge or binary.
func configurationJobID(owner, binary string, request deployansible.ExitRequest) (string, error) {
	return configurationAttemptJobID(owner, 0, binary, request)
}

func configurationAttemptJobID(
	owner string,
	attempt uint64,
	binary string,
	request deployansible.ExitRequest,
) (string, error) {
	return configurationInputsJobID(owner, attempt, binary, request, request)
}

func configurationInputsJobID(
	owner string,
	attempt uint64,
	binary string,
	request, files deployansible.ExitRequest,
) (string, error) {
	data, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	for _, value := range [][]byte{[]byte("ultra-exit-configuration-v1"), []byte(owner), data} {
		_, _ = fmt.Fprintf(hash, "%d:", len(value))
		_, _ = hash.Write(value)
	}
	// Zero keeps the identity of jobs submitted before attempt generations
	// existed. A saved explicit retry stays stable across relay/worker restarts.
	if attempt != 0 {
		_, _ = fmt.Fprintf(hash, "retry:%d:", attempt)
	}
	for _, path := range []string{binary, files.Identity, files.KnownHosts} {
		file, err := os.Open(path)
		if err != nil {
			return "", errors.New("configuration inputs unavailable")
		}
		digest := sha256.New()
		_, err = io.Copy(digest, file)
		_ = file.Close()
		if err != nil {
			return "", errors.New("configuration inputs unreadable")
		}
		_, _ = hash.Write(digest.Sum(nil))
	}
	sum := hash.Sum(nil)
	sum[6] = (sum[6] & 0x0f) | 0x50
	sum[8] = (sum[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", sum[:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16]), nil
}

func (p *Provisioner) Verify(ctx context.Context, op *cloud.Operation, instance cloud.Instance) error {
	node, e := db.NewExitNodeRepo(p.DB).Get(ctx, op.ExitID)
	if e != nil {
		return e
	}
	node.Enabled = true
	spec := *p.Bridge
	spec.Stats = nil
	strategy, e := mimic.New(spec.MimicPreset)
	if e != nil {
		return e
	}
	data, e := config.BuildBridgeXRayJSON(&spec, nil, []exits.Node{node}, node.ID, strategy, "none")
	if e != nil {
		return e
	}
	var raw map[string]any
	if e = json.Unmarshal(data, &raw); e != nil {
		return e
	}
	raw["inbounds"] = []any{}
	delete(raw, "api")
	delete(raw, "stats")
	raw["routing"] = map[string]any{"rules": []any{}}
	data, e = json.Marshal(raw)
	if e != nil {
		return e
	}
	var runner proxy.Runner
	if e = runner.StartJSON(data); e != nil {
		return errors.New("provisioning probe startup failed")
	}
	defer runner.Close() //nolint:errcheck
	return verifyTunnelWithRetry(ctx, func(probeCtx context.Context) exits.Health {
		return runner.ProbeExit(probeCtx, node, spec.HealthTargets())
	})
}

const (
	verifyRetryTimeout    = 2 * time.Minute
	verifyRetryInterval   = time.Second
	verifyRetryMaxBackoff = 10 * time.Second
	verifyConsecutiveOK   = 3
)

func verifyTunnelWithRetry(ctx context.Context, probe func(context.Context) exits.Health) error {
	return verifyTunnelWithRetryPolicy(
		ctx,
		probe,
		verifyRetryTimeout,
		verifyRetryInterval,
		verifyRetryMaxBackoff,
	)
}

func verifyTunnelWithRetryPolicy(
	ctx context.Context,
	probe func(context.Context) exits.Health,
	timeout, interval, maxBackoff time.Duration,
) error {
	retryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	backoff := interval
	consecutiveOK := 0
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		h := probe(retryCtx)
		lastErr = verifyHealth(h)
		if err := ctx.Err(); err != nil {
			return err
		}
		if retryCtx.Err() != nil {
			return verifyTimeoutError(lastErr)
		}
		if lastErr == nil {
			consecutiveOK++
			if consecutiveOK == verifyConsecutiveOK {
				return nil
			}
		} else {
			consecutiveOK = 0
		}
		timer := time.NewTimer(backoff)
		select {
		case <-retryCtx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
		}
		if retryCtx.Err() != nil {
			if err := ctx.Err(); err != nil {
				return err
			}
			return verifyTimeoutError(lastErr)
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func verifyTimeoutError(lastErr error) error {
	if lastErr != nil {
		return lastErr
	}
	return errors.New("tunnel verification timed out before consecutive health checks")
}

// Verification diagnostics deliberately exclude node identity and probe targets.
// Keep this separate from exits.Health: that type also contains addresses/URLs.
type verificationCheck struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	Bytes      int64  `json:"bytes"`
	DurationMS int64  `json:"duration_ms"`
}

type verificationError struct {
	reachable  bool
	internetOK bool
	checks     []verificationCheck
}

func (e *verificationError) CloudDiagnostics() map[string]any {
	return map[string]any{
		"reachable": e.reachable, "internet_ok": e.internetOK,
		"checks": append([]verificationCheck(nil), e.checks...),
	}
}

func (e *verificationError) Error() string {
	data, _ := json.Marshal(e.CloudDiagnostics()) // Only fixed strings, bools and integers.
	return "full tunnel check failed: " + string(data)
}

func verifyHealth(h exits.Health) error {
	if h.Reachable && h.InternetOK {
		return nil
	}
	e := &verificationError{reachable: h.Reachable, internetOK: h.InternetOK}
	for _, check := range h.Checks {
		code := check.Error
		switch code {
		case "http_status", "body_size", "response_failed", "tls_handshake_failed",
			"response_timeout", "tls_handshake_timeout", "deadline_or_cancel":
		default:
			code = "response_failed"
		}
		if check.OK {
			code = ""
		}
		e.checks = append(e.checks, verificationCheck{
			OK: check.OK, Error: code, Bytes: check.Bytes, DurationMS: check.DurationMS,
		})
	}
	return e
}

func (p *Provisioner) Publish(ctx context.Context, op *cloud.Operation) error {
	budget := db.NewQuotaRepo(p.DB)
	if e := budget.EnsureVultr(ctx, op.ExitID, op.InstanceID, int64(op.Offer.Plan.Bandwidth)*1_000_000_000); e != nil {
		return e
	}
	repo := db.NewExitNodeRepo(p.DB)
	enabled := true
	if _, e := repo.Update(ctx, op.ExitID, exits.UpdatePatch{Enabled: &enabled}); e != nil {
		return e
	}
	published, e := p.Routes.IsPublished(ctx, op.Offer.Region.ID, op.ExitID)
	if e != nil {
		return e
	}
	if !published {
		if e := p.Routes.Publish(ctx, op.Offer.Region.ID, op.Offer.Region.City+", "+op.Offer.Region.Country, op.ExitID); e != nil {
			return e
		}
	}
	if e := p.Exits.Refresh(ctx); e != nil {
		return e
	}
	return nil
}

// ApplyRoute is a separate durable stage from route publication. Publishing a
// location marks it unapplied; the marker is only set after the bridge has
// accepted the resulting runtime. A retry can therefore skip an apply whose
// receipt was committed before the caller lost its response.
func (p *Provisioner) ApplyRoute(ctx context.Context, op *cloud.Operation) error {
	if applied, err := p.Routes.IsApplied(ctx, op.ExitID); err != nil {
		return err
	} else if applied {
		return p.Refresh(ctx)
	}
	if e := p.Apply(ctx); e != nil {
		return e
	}
	if e := p.Routes.Applied(ctx, op.ExitID); e != nil {
		return e
	}
	return p.Refresh(ctx)
}

// ValidateRetirement refuses infrastructure and the persisted main/fallback exit.
// The caller additionally requires exact operation and provider ownership identities.
func (p *Provisioner) ValidateRetirement(ctx context.Context, op *cloud.Operation, instance cloud.Instance) error {
	return p.validateDeletion(ctx, op, instance, false)
}

func (p *Provisioner) validateDeletion(ctx context.Context, op *cloud.Operation, instance cloud.Instance, ordinary bool) error {
	if p.DB == nil || p.Bridge == nil || p.Bridge.Database == nil {
		return cloud.ErrUnavailable
	}
	primaryIP := net.ParseIP(p.Bridge.Database.PrimaryHost)
	if primaryIP == nil || primaryIP.To4() == nil {
		return cloud.ErrUnavailable
	}
	primaryHost := primaryIP.String()
	target := op.RetirementTarget
	if target == "" && op.Phase != "retire_unpublish" && op.Phase != "retire_delete" && op.Phase != "retire_cleanup" {
		target = instance.IP // pre-check callers; service persists it before effects
	}
	ip := net.ParseIP(target)
	if ip == nil || ip.To4() == nil || (instance.IP != "" && !sameRetirementAddress(target, instance.IP)) {
		return cloud.ErrConflict
	}
	if sameRetirementAddress(target, p.BridgeIP) ||
		sameRetirementAddress(target, p.Bridge.Exit.Address) ||
		sameRetirementAddress(target, primaryHost) {
		return cloud.ErrConflict
	}
	checked := *op
	checked.RetirementTarget = target
	repo := db.NewExitNodeRepo(p.DB)
	var validationErr error
	if ordinary {
		validationErr = repo.ValidateCloudDeleteTarget(ctx, &checked)
	} else {
		validationErr = repo.ValidateCloudRetirementTarget(ctx, &checked)
	}
	if validationErr != nil {
		return validationErr
	}
	budgets, err := db.NewQuotaRepo(p.DB).Budgets(ctx)
	if err != nil {
		return err
	}
	for _, budget := range budgets {
		if budget.ID == op.ExitID && budget.Fallback {
			return cloud.ErrConflict
		}
	}
	if op.ExitID == "" {
		return nil // paid resource has not installed a local exit yet
	}
	node, err := db.NewExitNodeRepo(p.DB).Get(ctx, op.ExitID)
	if errors.Is(err, db.ErrExitNotFound) {
		return nil // already removed locally; retain provider ownership checks
	}
	if err != nil {
		return err
	}
	// A saved delete checkpoint never authorizes deleting a republished node.
	if (op.Phase == "retire_delete" || op.Phase == "retire_cleanup" || op.Phase == "delete" || op.Phase == "cleanup") && node.Enabled {
		return cloud.ErrConflict
	}
	if sameRetirementAddress(node.Address, p.BridgeIP) ||
		sameRetirementAddress(node.Address, p.Bridge.Exit.Address) ||
		sameRetirementAddress(node.Address, primaryHost) ||
		(instance.IP != "" && !sameRetirementAddress(node.Address, instance.IP)) {
		return cloud.ErrConflict
	}
	return nil
}

func sameRetirementAddress(a, b string) bool {
	left, right := net.ParseIP(a), net.ParseIP(b)
	return left != nil && right != nil && left.Equal(right)
}

// ValidateDelete shares the retirement host checks with ordinary UI deletion.
// Older checkpoints may lack the saved address; recover it only from the exact
// provider instance or the still-reserved exit row before validating all aliases.
func (p *Provisioner) ValidateDelete(ctx context.Context, op *cloud.Operation) error {
	instance, err := p.API.Get(ctx, op.InstanceID)
	var api cloud.APIError
	missing := errors.As(err, &api) && api.Status == 404
	if err != nil && !missing {
		return err
	}
	if op.RetirementTarget == "" {
		op.RetirementTarget = instance.IP
		if missing && op.ExitID != "" {
			node, err := db.NewExitNodeRepo(p.DB).Get(ctx, op.ExitID)
			if err != nil && !errors.Is(err, db.ErrExitNotFound) {
				return err
			}
			op.RetirementTarget = node.Address
		}
	}
	if missing {
		instance = cloud.Instance{ID: op.InstanceID, IP: op.RetirementTarget}
		if op.ExitID == "" && op.RetirementTarget == "" {
			return nil // no provider machine and no published route
		}
	}
	switch op.Phase {
	case "unpublish", "delete", "cleanup":
	default:
		return cloud.ErrConflict
	}
	return p.validateDeletion(ctx, op, instance, true)
}

func (p *Provisioner) Unpublish(ctx context.Context, op *cloud.Operation) error {
	if op.ExitID == "" {
		return nil
	}
	disabled := false
	repo := db.NewExitNodeRepo(p.DB)
	var err error
	if op.Phase == "retire_unpublish" {
		err = repo.DisableCloudRetirement(ctx, op)
	} else {
		_, err = repo.Update(ctx, op.ExitID, exits.UpdatePatch{Enabled: &disabled})
	}
	if err != nil && !errors.Is(err, db.ErrExitNotFound) {
		return routeRemovalError(err)
	}
	if e := p.Routes.Unpublish(ctx, op.ExitID); e != nil {
		return e
	}
	if e := p.Exits.Refresh(ctx); e != nil {
		return e
	}
	return p.Apply(ctx)
}

func routeRemovalError(err error) error {
	if errors.Is(err, db.ErrExitLastEnabled) {
		return errors.Join(cloud.ErrLastEnabledExit, err)
	}
	return err
}

func (p *Provisioner) Cleanup(ctx context.Context, op *cloud.Operation) error {
	return p.API.DeleteFirewall(ctx, op.FirewallID)
}
