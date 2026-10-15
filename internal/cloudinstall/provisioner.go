package cloudinstall

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
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
	return install.Remote{Host: instance.IP, Identity: p.Identity, KnownHosts: filepath.Join(dir, "known_hosts")}, nil
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
		TunnelTLSProvision: p.Bridge.TunnelTLSProvision,
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

func (p *Provisioner) Install(ctx context.Context, op *cloud.Operation, instance cloud.Instance) error {
	c, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	remote, e := p.remote(op, instance)
	if e != nil {
		return e
	}
	for {
		if _, e = remote.Run(c, "true"); e == nil {
			break
		}
		select {
		case <-c.Done():
			return c.Err()
		case <-time.After(5 * time.Second):
		}
	}
	node, e := p.node(c, op, instance)
	if e != nil {
		return e
	}
	spec := p.exitSpec(node)
	if e = spec.Validate(); e != nil {
		return errors.New("generated exit spec invalid")
	}
	if p.Configurer == nil {
		return errors.New("ansible controller required")
	}
	request := deployansible.ExitRequest{
		Host: instance.IP, User: "root", Identity: p.Identity, KnownHosts: remote.KnownHosts, BridgeIPv4: p.BridgeIP, Spec: spec,
	}
	binary := filepath.Join(p.StateDir, op.ID, "ultra-relay")
	result, err := p.configureExit(c, op, binary, request)
	if err != nil {
		return err
	}
	if err = p.Routes.SetPin(c, node.ID, result.CertPin); err != nil {
		return err
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
	return p.Configurer.ConfigureExit(ctx, jobID, binary, request)
}

// Purchase identity stays stable; a changed desired configuration needs a new
// immutable job instead of reusing a receipt for the former bridge or binary.
func configurationJobID(owner, binary string, request deployansible.ExitRequest) (string, error) {
	return configurationAttemptJobID(owner, 0, binary, request)
}

func configurationAttemptJobID(owner string, attempt uint64, binary string, request deployansible.ExitRequest) (string, error) {
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
	for _, path := range []string{binary, request.Identity, request.KnownHosts} {
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
	for i := 0; i < 3; i++ {
		h := runner.ProbeExit(ctx, node, spec.HealthTargets())
		if !h.Reachable || !h.InternetOK {
			return errors.New("full tunnel check failed")
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return nil
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
	if e := p.Routes.Publish(ctx, op.Offer.Region.ID, op.Offer.Region.City+", "+op.Offer.Region.Country, op.ExitID); e != nil {
		return e
	}
	if e := p.Exits.Refresh(ctx); e != nil {
		return e
	}
	if e := p.Apply(ctx); e != nil {
		return e
	}
	if e := p.Routes.Applied(ctx, op.ExitID); e != nil {
		return e
	}
	return p.Refresh(ctx)
}
func (p *Provisioner) Unpublish(ctx context.Context, op *cloud.Operation) error {
	if op.ExitID == "" {
		return nil
	}
	disabled := false
	if _, e := db.NewExitNodeRepo(p.DB).Update(ctx, op.ExitID, exits.UpdatePatch{Enabled: &disabled}); e != nil &&
		!errors.Is(e, db.ErrExitNotFound) {
		return e
	}
	if e := p.Routes.Unpublish(ctx, op.ExitID); e != nil {
		return e
	}
	if e := p.Exits.Refresh(ctx); e != nil {
		return e
	}
	return p.Apply(ctx)
}
func (p *Provisioner) Cleanup(ctx context.Context, op *cloud.Operation) error {
	return p.API.DeleteFirewall(ctx, op.FirewallID)
}
