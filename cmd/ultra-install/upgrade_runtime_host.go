package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
	"io"
	"net"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// The request excludes credentials, runtime JSON, environment and file paths.
// A transport must decode strictly and emit only runtimeHostResult. Services
// and coordinated fleet activation are the caller's responsibility.
type runtimeHostRequest struct {
	Transaction string                     `json:"transaction"`
	Role        config.Role                `json:"role"`
	Node        string                     `json:"node"`
	Bridge      installplan.BridgeConfig   `json:"bridge"`
	Exits       []runtimeHostExit          `json:"exits"`
	Database    installplan.DatabaseConfig `json:"database"`
	Features    installplan.FeatureConfig  `json:"features"`
	BotEnabled  bool                       `json:"bot_enabled"`
	Proof       *runtimeHostExitProof      `json:"proof,omitempty"`
}

// The pinned-SSH caller must bind this proof to inspect-upgrade's bridge node
// record and frozen target inventory. It must reject changed topology before
// sending any request. Digests are public evidence, never raw tunnel UUIDs.
type runtimeHostExitProof struct {
	Node                 string `json:"node"`
	SSHHost              string `json:"ssh_host"`
	DesiredIdentity      string `json:"desired_identity"`
	TunnelIdentityDigest string `json:"tunnel_identity_digest"`
	CertificatePin       string `json:"certificate_pin,omitempty"`
	NodeID               string `json:"node_id,omitempty"`
	TopologySHA          string `json:"topology_sha256,omitempty"`
}
type runtimeHostExit struct {
	Name     string `json:"name"`
	SSHHost  string `json:"ssh_host"`
	DialAddr string `json:"dial_addr"`
	Port     int    `json:"port"`
}
type runtimeHostResult struct {
	Status string `json:"status"`
}

// The host records this private baseline only after authoritative local recovery
// metadata proves desired identity. Never initialize it from desired config alone.
type runtimeHostAttestation struct {
	DesiredIdentity string `json:"desired_identity"`
	RuntimeIdentity string `json:"runtime_identity"`
}
type runtimeHostImage struct {
	Exists bool
	Data   []byte
	Mode   uint32
	UID    uint32
	GID    uint32
}
type runtimeHostJournal struct {
	Version     int
	Transaction string
	State       string
	Before      []runtimeHostImage
	Candidate   []runtimeHostImage
}
type runtimeHostStore struct{ root string }

func newRuntimeHostStore() runtimeHostStore        { return runtimeHostStore{root: "/"} }
func (s runtimeHostStore) path(name string) string { return filepath.Join(s.root, name) }

var runtimeHostFiles = []string{"etc/ultra-relay/spec.json", "etc/ultra-relay/environment"}

const runtimeHostStateDir = "etc/ultra-recovery/runtime-transactions"
const runtimeHostIdentityFile = "etc/ultra-recovery/runtime-identity.json"

func runtimeHostError(code string) error { return errors.New("runtime_" + code) }
func runtimeHostDigest(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Canonical identity excludes ports and optional runtime tuning. Membership,
// bridge location and database identity are immutable within an upgrade.
func runtimeHostDesiredIdentity(r runtimeHostRequest) (string, error) {
	if r.Role != config.RoleBridge && r.Role != config.RoleExit {
		return "", runtimeHostError("identity_uncertain")
	}
	type member struct{ Name, SSHHost, DialAddr string }
	members := make([]member, 0, len(r.Exits))
	seen := map[string]bool{}
	for _, ex := range r.Exits {
		if ex.Name == "" || ex.SSHHost == "" || ex.DialAddr == "" || seen[ex.Name] {
			return "", runtimeHostError("identity_uncertain")
		}
		seen[ex.Name] = true
		members = append(members, member{ex.Name, ex.SSHHost, ex.DialAddr})
	}
	dynamic := r.Role == config.RoleExit && r.Node == "" && r.Proof != nil && runtimeHostDynamicProofValid(r.Proof)
	if len(members) == 0 || r.Bridge.Address == "" || r.Bridge.SSHHost == "" || (r.Role == config.RoleExit && !seen[r.Node] && !dynamic) {
		return "", runtimeHostError("identity_uncertain")
	}
	sort.Slice(members, func(i, j int) bool { return members[i].Name < members[j].Name })
	identity := runtimeHostDigest(struct {
		Role                           config.Role
		Node, BridgeAddress, BridgeSSH string
		Members                        []member
		DB                             installplan.DatabaseConfig
	}{r.Role, r.Node, r.Bridge.Address, r.Bridge.SSHHost, members, r.Database})
	if dynamic {
		return runtimeHostDigest(struct{ Identity, NodeID, SSHHost string }{identity, r.Proof.NodeID, r.Proof.SSHHost}), nil
	}
	return identity, nil
}
func runtimeHostInstalledIdentity(raw []byte) (string, error) {
	var doc map[string]json.RawMessage
	if json.Unmarshal(raw, &doc) != nil || doc == nil {
		return "", runtimeHostError("identity_uncertain")
	}
	identity := map[string]json.RawMessage{}
	for _, key := range []string{"role", "reality", "database"} {
		identity[key] = doc[key]
	}
	var reality map[string]json.RawMessage
	if len(doc["reality"]) > 0 {
		if json.Unmarshal(doc["reality"], &reality) != nil {
			return "", runtimeHostError("identity_uncertain")
		}
		delete(reality, "dest")
		delete(reality, "server_names")
		identity["reality"], _ = json.Marshal(reality)
	}
	var exit map[string]json.RawMessage
	if json.Unmarshal(doc["exit"], &exit) != nil || exit == nil {
		return "", runtimeHostError("identity_uncertain")
	}
	delete(exit, "port")
	identity["exit"], _ = json.Marshal(exit)
	return runtimeHostDigest(identity), nil
}
func (s runtimeHostStore) trustedParent(path string) error {
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return runtimeHostError("file_untrusted")
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		ownerAllowed := ok && st.Uid == uint32(os.Geteuid())
		if ok && p == s.path("etc/ultra-relay") && info.Mode().Perm() == 0700 {
			if relay, lookupErr := user.Lookup("ultra-relay"); lookupErr == nil {
				if uid, parseErr := strconv.ParseUint(relay.Uid, 10, 32); parseErr == nil && st.Uid == uint32(uid) {
					ownerAllowed = true
				}
			}
		}
		if !ownerAllowed || info.Mode().Perm()&0022 != 0 {
			return runtimeHostError("file_untrusted")
		}
		if p == filepath.Clean(s.root) {
			break
		}
		if filepath.Dir(p) == p {
			return runtimeHostError("file_untrusted")
		}
	}
	return nil
}
func (s runtimeHostStore) image(path string) (runtimeHostImage, error) {
	if err := s.trustedParent(path); err != nil {
		return runtimeHostImage{}, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		return runtimeHostImage{}, nil
	}
	if err != nil {
		return runtimeHostImage{}, runtimeHostError("file_untrusted")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close() //nolint:errcheck
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 || info.Mode().Perm()&0022 != 0 {
		return runtimeHostImage{}, runtimeHostError("file_untrusted")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 {
		return runtimeHostImage{}, runtimeHostError("file_untrusted")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	if err != nil || len(raw) > 4<<20 {
		return runtimeHostImage{}, runtimeHostError("file_untrusted")
	}
	return runtimeHostImage{true, raw, uint32(info.Mode()), st.Uid, st.Gid}, nil
}
func runtimeHostSyncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close() //nolint:errcheck
	return d.Sync()
}
func (s runtimeHostStore) persist(path string, image runtimeHostImage) error {
	if err := s.trustedParent(path); err != nil {
		return err
	}
	if !image.Exists {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return runtimeHostError("write_failed")
		}
		if runtimeHostSyncDir(filepath.Dir(path)) != nil {
			return runtimeHostError("write_failed")
		}
		return nil
	}
	tempDir := filepath.Dir(path)
	if filepath.Dir(path) == s.path("etc/ultra-relay") {
		tempDir = s.path("etc/ultra-recovery")
	}
	f, err := os.CreateTemp(tempDir, ".runtime-")
	if err != nil {
		return runtimeHostError("write_failed")
	}
	name := f.Name()
	defer os.Remove(name) //nolint:errcheck
	if err = f.Chown(int(image.UID), int(image.GID)); err == nil {
		err = f.Chmod(os.FileMode(image.Mode))
	}
	if err == nil {
		_, err = f.Write(image.Data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return runtimeHostError("write_failed")
	}
	if os.Rename(name, path) != nil || runtimeHostSyncDir(filepath.Dir(path)) != nil {
		return runtimeHostError("write_failed")
	}
	return nil
}
func (s runtimeHostStore) journalPath(id string) (string, error) {
	if id == "" || len(id) > 80 {
		return "", runtimeHostError("request_invalid")
	}
	for _, ch := range id {
		if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
			return "", runtimeHostError("request_invalid")
		}
	}
	return s.path(runtimeHostStateDir + "/" + id + ".json"), nil
}
func (s runtimeHostStore) saveJournal(path string, j runtimeHostJournal) error {
	raw, err := json.Marshal(j)
	if err != nil {
		return runtimeHostError("journal_invalid")
	}
	return s.persist(path, runtimeHostImage{true, raw, 0600, uint32(os.Geteuid()), uint32(os.Getegid())})
}
func (s runtimeHostStore) locked(fn func() (runtimeHostResult, error)) (runtimeHostResult, error) {
	dir := s.path("etc")
	if err := s.trustedParent(filepath.Join(dir, "lock")); err != nil {
		return runtimeHostResult{}, err
	}
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return runtimeHostResult{}, runtimeHostError("lock_failed")
	}
	defer syscall.Close(fd) //nolint:errcheck
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 || st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return runtimeHostResult{}, runtimeHostError("lock_failed")
	}
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return runtimeHostResult{}, runtimeHostError("busy")
	}
	defer syscall.Flock(fd, syscall.LOCK_UN) //nolint:errcheck
	return fn()
}
func (s runtimeHostStore) prepare(r runtimeHostRequest) (runtimeHostResult, error) {
	return s.locked(func() (runtimeHostResult, error) {
		path, err := s.journalPath(r.Transaction)
		if err != nil {
			return runtimeHostResult{}, err
		}
		if _, statErr := os.Lstat(s.path(runtimeHostStateDir)); statErr == nil {
			existing, readErr := s.image(path)
			if readErr != nil {
				return runtimeHostResult{}, readErr
			}
			if existing.Exists {
				return runtimeHostResult{}, runtimeHostError("transaction_exists")
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return runtimeHostResult{}, runtimeHostError("file_untrusted")
		}

		identity, err := runtimeHostDesiredIdentity(r)
		if err != nil {
			return runtimeHostResult{}, err
		}
		if r.Role == config.RoleExit && r.Proof != nil {
			if _, proofErr := s.liveExitAttestation(r); proofErr != nil {
				return runtimeHostResult{}, proofErr
			}
		}
		var att runtimeHostImage
		if _, stateErr := os.Lstat(s.path("etc/ultra-recovery")); stateErr == nil {
			att, err = s.image(s.path(runtimeHostIdentityFile))
			if err != nil {
				return runtimeHostResult{}, err
			}
		} else if !errors.Is(stateErr, os.ErrNotExist) {
			return runtimeHostResult{}, runtimeHostError("file_untrusted")
		}

		var baseline runtimeHostAttestation
		bootstrap := !att.Exists
		if bootstrap {
			if r.Role == config.RoleExit {
				baseline, err = s.liveExitAttestation(r)
			} else {
				baseline, err = s.liveBridgeAttestation(r)
			}
			if err != nil {
				return runtimeHostResult{}, err
			}
		} else if att.UID != uint32(os.Geteuid()) || att.Mode != 0600 || json.Unmarshal(att.Data, &baseline) != nil {
			return runtimeHostResult{}, runtimeHostError("identity_uncertain")
		}
		if baseline.DesiredIdentity != identity || baseline.RuntimeIdentity == "" {
			return runtimeHostResult{}, runtimeHostError("migration_required")
		}
		j := runtimeHostJournal{Version: 1, Transaction: r.Transaction, State: "prepared"}
		for _, file := range runtimeHostFiles {
			img, e := s.image(s.path(file))
			if e != nil {
				return runtimeHostResult{}, e
			}
			j.Before = append(j.Before, img)
		}
		if !j.Before[0].Exists || (r.Role == config.RoleBridge && !j.Before[1].Exists) {
			return runtimeHostResult{}, runtimeHostError("file_unavailable")
		}
		installed, err := runtimeHostInstalledIdentity(j.Before[0].Data)
		if err != nil || installed != baseline.RuntimeIdentity {
			return runtimeHostResult{}, runtimeHostError("migration_required")
		}
		p := &installplan.InstallPlan{SchemaVersion: 1, SourceValues: map[string]string{}, Bridge: r.Bridge, Database: r.Database, Features: r.Features, Bot: installplan.BotConfig{Enabled: r.BotEnabled}}
		p.Bridge.ReuseSpec = true
		for _, ex := range r.Exits {
			p.Exits = append(p.Exits, installplan.ExitNode{Name: ex.Name, SSHHost: ex.SSHHost, DialAddr: ex.DialAddr, Port: ex.Port})
		}
		if installplan.ValidateLocalRuntimePlan(p) != nil {
			return runtimeHostResult{}, runtimeHostError("request_invalid")
		}
		projected, err := installplan.ProjectLocalRuntime(p, j.Before[0].Data, r.Role, r.Node)
		if err != nil {
			return runtimeHostResult{}, runtimeHostError("projection_failed")
		}
		afterIdentity, err := runtimeHostInstalledIdentity(projected.SpecJSON)
		if err != nil || afterIdentity != installed {
			return runtimeHostResult{}, runtimeHostError("migration_required")
		}
		j.Candidate = append(j.Candidate, j.Before...)
		j.Candidate[0].Data = projected.SpecJSON
		env := j.Before[1]
		env.Exists = true
		if !j.Before[1].Exists {
			env.Mode = 0600
			env.UID = uint32(os.Geteuid())
			env.GID = uint32(os.Getegid())
		}
		var lines []string
		for _, line := range strings.Split(string(env.Data), "\n") {
			key, _, ok := strings.Cut(line, "=")
			if ok && strings.TrimSpace(key) == "ULTRA_RELAY_LOG_LEVEL" {
				continue
			}
			lines = append(lines, line)
		}
		env.Data = []byte(strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\nULTRA_RELAY_LOG_LEVEL=" + p.Features.LogLevel + "\n")
		j.Candidate[1] = env
		if _, stateErr := os.Lstat(s.path("etc/ultra-recovery")); errors.Is(stateErr, os.ErrNotExist) {
			if os.Mkdir(s.path("etc/ultra-recovery"), 0700) != nil || runtimeHostSyncDir(s.path("etc")) != nil {
				return runtimeHostResult{}, runtimeHostError("write_failed")
			}
		}
		if _, statErr := os.Lstat(s.path(runtimeHostStateDir)); errors.Is(statErr, os.ErrNotExist) {
			if os.Mkdir(s.path(runtimeHostStateDir), 0700) != nil || runtimeHostSyncDir(s.path("etc/ultra-recovery")) != nil {
				return runtimeHostResult{}, runtimeHostError("write_failed")
			}
		}
		if bootstrap {
			raw, _ := json.Marshal(baseline)
			if err = s.persist(s.path(runtimeHostIdentityFile), runtimeHostImage{true, raw, 0600, uint32(os.Geteuid()), uint32(os.Getegid())}); err != nil {
				return runtimeHostResult{}, err
			}
		}
		if err = s.saveJournal(path, j); err != nil {
			return runtimeHostResult{}, err
		}
		return runtimeHostResult{Status: "prepared"}, nil
	})
}
func (s runtimeHostStore) transition(id string, rollback bool) (runtimeHostResult, error) {
	return s.locked(func() (runtimeHostResult, error) {
		path, err := s.journalPath(id)
		if err != nil {
			return runtimeHostResult{}, err
		}
		saved, err := s.image(path)
		if err != nil || !saved.Exists || saved.Mode != 0600 || saved.UID != uint32(os.Geteuid()) {
			return runtimeHostResult{}, runtimeHostError("journal_invalid")
		}
		var j runtimeHostJournal
		if json.Unmarshal(saved.Data, &j) != nil || j.Version != 1 || j.Transaction != id || len(j.Before) != len(runtimeHostFiles) || len(j.Candidate) != len(runtimeHostFiles) {
			return runtimeHostResult{}, runtimeHostError("journal_invalid")
		}
		if j.State != "prepared" && j.State != "applied" && j.State != "rolled_back" {
			return runtimeHostResult{}, runtimeHostError("journal_invalid")
		}
		if !rollback && j.State == "rolled_back" {
			return runtimeHostResult{}, runtimeHostError("transaction_finished")
		}
		// Validate the entire set before mutation. Mixed before/candidate states after
		// a process crash are recoverable; third states require operator resolution.
		for i, file := range runtimeHostFiles {
			current, e := s.image(s.path(file))
			if e != nil {
				return runtimeHostResult{}, e
			}
			if !runtimeHostImagesEqual(current, j.Before[i]) && !runtimeHostImagesEqual(current, j.Candidate[i]) {
				return runtimeHostResult{}, runtimeHostError("third_state")
			}
		}
		target := j.Candidate
		j.State = "applied"
		if rollback {
			target = j.Before
			j.State = "rolled_back"
		}
		for i, file := range runtimeHostFiles {
			if err = s.persist(s.path(file), target[i]); err != nil {
				return runtimeHostResult{}, err
			}
		}
		if err = s.saveJournal(path, j); err != nil {
			return runtimeHostResult{}, err
		}
		return runtimeHostResult{Status: j.State}, nil
	})
}
func runtimeHostImagesEqual(a, b runtimeHostImage) bool {
	return a.Exists == b.Exists && bytes.Equal(a.Data, b.Data) && a.Mode == b.Mode && a.UID == b.UID && a.GID == b.GID
}

// Bootstrap is supported only where trusted recovery metadata proves the full
// public topology. Exit spec alone cannot attest membership; that requires the
// bridge's authenticated node identity contract before this helper may bootstrap.
func (s runtimeHostStore) liveBridgeAttestation(r runtimeHostRequest) (runtimeHostAttestation, error) {
	fail := func() (runtimeHostAttestation, error) {
		return runtimeHostAttestation{}, runtimeHostError("identity_uncertain")
	}
	if r.Role != config.RoleBridge {
		return runtimeHostAttestation{}, runtimeHostError("exit_attestation_required")
	}
	type metadata struct {
		BridgeIPv4   string                       `json:"bridge_ipv4"`
		Database     string                       `json:"database"`
		DatabaseHost string                       `json:"database_host"`
		Nodes        []installplan.AutomationNode `json:"static_nodes"`
		Provider     string                       `json:"bridge_provider"`
		URL          string                       `json:"bridge_url"`
	}
	var deployment, reconcile metadata
	for _, entry := range []struct {
		path  string
		value *metadata
	}{{"etc/ultra-recovery/deployment.json", &deployment}, {"etc/ultra-recovery/reconcile.json", &reconcile}} {
		img, err := s.image(s.path(entry.path))
		if err != nil || !img.Exists || img.UID != uint32(os.Geteuid()) || img.Mode&0077 != 0 || json.Unmarshal(img.Data, entry.value) != nil {
			return fail()
		}
	}
	if deployment.BridgeIPv4 == "" || deployment.BridgeIPv4 != r.Bridge.Address || r.Bridge.SSHHost != r.Bridge.Address || deployment.Database == "" || deployment.Database != reconcile.Database || deployment.Database != r.Database.Name || deployment.DatabaseHost != r.Database.PrimaryHost || reconcile.DatabaseHost != r.Database.PrimaryHost || !r.Database.Enabled || deployment.Provider == "" || deployment.Provider != reconcile.Provider || deployment.URL != reconcile.URL || !reflect.DeepEqual(deployment.Nodes, reconcile.Nodes) || len(deployment.Nodes) != len(r.Exits) {
		return runtimeHostAttestation{}, runtimeHostError("migration_required")
	}
	seen := map[string]bool{}
	for _, node := range deployment.Nodes {
		if node.Name == "" || node.Address == "" || seen[node.Name] {
			return fail()
		}
		seen[node.Name] = true
		found := false
		for _, ex := range r.Exits {
			if ex.Name == node.Name && ex.SSHHost == node.Address && ex.DialAddr == node.Address {
				found = true
			}
		}
		if !found {
			return runtimeHostAttestation{}, runtimeHostError("migration_required")
		}
	}
	img, err := s.image(s.path(runtimeHostFiles[0]))
	if err != nil || !img.Exists {
		return fail()
	}
	var spec config.Spec
	if json.Unmarshal(img.Data, &spec) != nil || spec.Role != config.RoleBridge || spec.Database == nil {
		return fail()
	}
	// URL DSNs are self-contained. Unsupported libpq forms fail closed rather
	// than consulting process environment defaults or exposing parse errors.
	u, err := url.Parse(spec.Database.DSN)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.User == nil || u.Hostname() == "" {
		return fail()
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return fail()
	}
	for key := range query {
		if key != "sslmode" && key != "connect_timeout" && key != "application_name" {
			return fail()
		}
	}
	if u.Port() != "25432" || u.Hostname() != "127.0.0.1" || r.Database.PrimaryHost == "" || r.Database.PrimaryHost == r.Bridge.Address || strings.TrimPrefix(u.Path, "/") != r.Database.Name || u.User.Username() != r.Database.User || r.Database.ReplicaHost != "" {
		return runtimeHostAttestation{}, runtimeHostError("migration_required")
	}
	desired, err := runtimeHostDesiredIdentity(r)
	if err != nil {
		return fail()
	}
	installed, err := runtimeHostInstalledIdentity(img.Data)
	if err != nil {
		return fail()
	}
	return runtimeHostAttestation{desired, installed}, nil
}

func runtimeHostValidDigest(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == sha256.Size && value == strings.ToLower(value)
}
func runtimeHostDynamicProofValid(proof *runtimeHostExitProof) bool {
	if proof == nil || proof.Node != "" || len(proof.NodeID) != 36 || net.ParseIP(proof.SSHHost) == nil || !runtimeHostValidDigest(proof.TopologySHA) {
		return false
	}
	for i, ch := range proof.NodeID {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if ch != '-' {
				return false
			}
			continue
		}
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}
func (s runtimeHostStore) liveExitAttestation(r runtimeHostRequest) (runtimeHostAttestation, error) {
	fail := func() (runtimeHostAttestation, error) {
		return runtimeHostAttestation{}, runtimeHostError("exit_attestation_required")
	}
	proof := r.Proof
	if proof == nil || proof.Node != r.Node || !runtimeHostValidDigest(proof.DesiredIdentity) || !runtimeHostValidDigest(proof.TunnelIdentityDigest) {
		return fail()
	}
	desired, err := runtimeHostDesiredIdentity(r)
	if err != nil || desired != proof.DesiredIdentity {
		return fail()
	}
	found := false
	for _, ex := range r.Exits {
		if ex.Name == r.Node && ex.SSHHost == proof.SSHHost {
			found = true
		}
	}
	if !found && (r.Node != "" || !runtimeHostDynamicProofValid(proof)) {
		return fail()
	}
	img, err := s.image(s.path(runtimeHostFiles[0]))
	if err != nil || !img.Exists {
		return fail()
	}
	var spec config.Spec
	if json.Unmarshal(img.Data, &spec) != nil || spec.Role != config.RoleExit || spec.Exit.TunnelUUID == "" {
		return fail()
	}
	sum := sha256.Sum256([]byte(spec.Exit.TunnelUUID))
	if hex.EncodeToString(sum[:]) != proof.TunnelIdentityDigest {
		return fail()
	}
	if proof.CertificatePin != "" {
		if !runtimeHostValidDigest(proof.CertificatePin) || spec.ExitCertPaths.CertFile != "/etc/ultra-relay/fullchain.pem" {
			return fail()
		}
		certImage, readErr := s.image(s.path("etc/ultra-relay/fullchain.pem"))
		if readErr != nil || !certImage.Exists {
			return fail()
		}
		block, _ := pem.Decode(certImage.Data)
		if block == nil || block.Type != "CERTIFICATE" {
			return fail()
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return fail()
		}
		pin := sha256.Sum256(cert.Raw)
		if hex.EncodeToString(pin[:]) != proof.CertificatePin {
			return fail()
		}
	}
	installed, err := runtimeHostInstalledIdentity(img.Data)
	if err != nil {
		return fail()
	}
	return runtimeHostAttestation{desired, installed}, nil
}
