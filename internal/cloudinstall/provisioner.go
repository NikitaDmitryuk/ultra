package cloudinstall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/install"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/NikitaDmitryuk/ultra/internal/proxy"
)

type Provisioner struct {
	CheckReady                           func(context.Context) error
	RemoveReplica                        func(context.Context, string) error
	API                                  *cloud.Vultr
	DB                                   *db.DB
	Bridge                               *config.Spec
	Exits                                *exits.Manager
	Routes                               *db.RouteRepo
	Identity, StateDir, BridgeIP, Binary string
	Apply                                func(context.Context) error
	Refresh                              func(context.Context) error
	Replica                              func(context.Context, string, install.Remote) (string, error)
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
	if p.CheckReady == nil || p.Replica == nil {
		return cloud.CreateRequest{}, errors.New("replication setup required")
	}
	if e := p.CheckReady(ctx); e != nil {
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
	n, e = repo.Add(ctx, exits.AddParams{ID: op.ID, Name: "vultr-" + op.Offer.Region.ID, Address: instance.IP, Port: p.port(), Priority: 200, Enabled: &disabled, CountryCode: op.Offer.Region.Country, CountryName: op.Offer.Region.Country, City: op.Offer.Region.City, DisplayName: op.Offer.Region.City + ", " + op.Offer.Region.Country})
	if e == nil {
		op.ExitID = n.ID
	}
	return n, e
}
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
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
	spec := config.Spec{
		SchemaVersion: config.CurrentSpecSchemaVersion, Role: config.RoleExit,
		MimicPreset: p.Bridge.MimicPreset, ListenAddress: "0.0.0.0", VLESSPort: node.Port,
		SplithttpHost: p.Bridge.SplithttpHost, SplithttpPath: p.Bridge.SplithttpPath,
		SplitHTTPTLS: p.Bridge.SplitHTTPTLS, TunnelTransport: p.Bridge.TunnelTransport,
		TunnelTLSProvision: p.Bridge.TunnelTLSProvision,
		Exit:               config.ExitTunnelSpec{TunnelUUID: node.TunnelUUID},
		ExitCertPaths:      config.CertPaths{CertFile: "/etc/ultra-relay/fullchain.pem", KeyFile: "/etc/ultra-relay/privkey.pem"},
	}
	if p.Bridge.AntiCensor != nil {
		anti := *p.Bridge.AntiCensor
		anti.WARPProxy = false
		anti.PublicXHTTPPort = 0
		spec.AntiCensor = &anti
	}
	if e = spec.Validate(); e != nil {
		return errors.New("generated exit spec invalid")
	}
	data, e := json.Marshal(spec)
	if e != nil {
		return e
	}
	_, e = remote.Run(c, `set -eu
id -u ultra-relay >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin ultra-relay
install -d -o ultra-relay -g ultra-relay -m 700 /etc/ultra-relay
`)
	if e != nil {
		return e
	}
	binary, e := os.Open(filepath.Join(p.StateDir, op.ID, "ultra-relay"))
	if e != nil {
		return e
	}
	defer binary.Close() //nolint:errcheck
	h := sha256.New()
	if _, e = io.Copy(h, binary); e != nil {
		return e
	}
	checksum := hex.EncodeToString(h.Sum(nil))
	if _, e = binary.Seek(0, io.SeekStart); e != nil {
		return e
	}
	if e = remote.Upload(c, "/etc/ultra-relay/ultra-relay.next", binary); e != nil {
		return e
	}
	if e = remote.Upload(c, "/etc/ultra-relay/spec.next", bytes.NewReader(data)); e != nil {
		return e
	}
	if e = remote.Upload(c, "/etc/systemd/system/ultra-relay.service", strings.NewReader(install.RelaySystemdUnit)); e != nil {
		return e
	}
	_, e = remote.Run(c, `set -eu
echo "`+checksum+`  /etc/ultra-relay/ultra-relay.next" | sha256sum -c - >/dev/null
if [ ! -s /etc/ultra-relay/fullchain.pem ]; then
 openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -keyout /etc/ultra-relay/privkey.pem -out /etc/ultra-relay/fullchain.pem -subj `+quote("/CN="+spec.SplithttpHost)+` -addext `+quote("subjectAltName=DNS:"+spec.SplithttpHost)+` >/dev/null 2>&1
fi
chown ultra-relay:ultra-relay /etc/ultra-relay/*.pem
chmod 600 /etc/ultra-relay/*.pem
install -o ultra-relay -g ultra-relay -m 600 /etc/ultra-relay/spec.next /etc/ultra-relay/spec.json
install -o ultra-relay -g ultra-relay -m 755 /etc/ultra-relay/ultra-relay.next /usr/local/bin/ultra-relay
printf 'ULTRA_RELAY_LOG_LEVEL=info\n' > /etc/ultra-relay/environment
chown ultra-relay:ultra-relay /etc/ultra-relay/environment
chmod 600 /etc/ultra-relay/environment
rm -f /etc/ultra-relay/spec.next /etc/ultra-relay/ultra-relay.next
systemctl daemon-reload
systemctl enable ultra-relay >/dev/null 2>&1
systemctl restart ultra-relay
systemctl is-active --quiet ultra-relay
`)
	if e != nil {
		return e
	}
	pin, e := remote.Run(c, `openssl x509 -noout -fingerprint -sha256 -in /etc/ultra-relay/fullchain.pem | sed 's/.*=//' | tr -d ':' | tr '[:upper:]' '[:lower:]'`)
	if e != nil {
		return e
	}
	fingerprint := strings.TrimSpace(string(pin))
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(fingerprint) {
		return errors.New("invalid certificate fingerprint")
	}
	if e = p.Routes.SetPin(c, node.ID, fingerprint); e != nil {
		return e
	}
	// Replica bootstrap runs in its own monitor after publication; checkpoint I/O
	// must not hold the cloud operation lock or delay cancellation for minutes.
	op.ReplicationState = "not_configured"

	return nil
}
func (p *Provisioner) Verify(ctx context.Context, op *cloud.Operation, instance cloud.Instance) error {
	node, e := db.NewExitNodeRepo(p.DB).Get(ctx, op.ExitID)
	if e != nil {
		return e
	}
	node.Enabled = true
	spec := *p.Bridge
	spec.Stats = nil
	spec.SOCKS5 = nil
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
	if _, e := db.NewExitNodeRepo(p.DB).Update(ctx, op.ExitID, exits.UpdatePatch{Enabled: &disabled}); e != nil && !errors.Is(e, db.ErrExitNotFound) {
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
	if p.RemoveReplica != nil {
		if e := p.RemoveReplica(ctx, op.ExitID); e != nil {
			return e
		}
	}
	return p.API.DeleteFirewall(ctx, op.FirewallID)
}
