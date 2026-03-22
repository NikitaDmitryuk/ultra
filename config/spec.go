package config

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
)

// CurrentSpecSchemaVersion is bumped when JSON fields or semantics change incompatibly.
const CurrentSpecSchemaVersion = 1

// TunnelTLSProvision describes how the exit node obtained TLS credentials for bridge→exit splithttp.
// See deploy/TLS.md. Empty means unspecified (legacy configs).
type TunnelTLSProvision string

const (
	TunnelTLSACME       TunnelTLSProvision = "acme_letsencrypt"
	TunnelTLSUserProv   TunnelTLSProvision = "user_provided"
	TunnelTLSSelfSigned TunnelTLSProvision = "self_signed"
)

// Role selects bridge (outer) or exit (upstream-facing) node profile.
type Role string

const (
	RoleBridge Role = "bridge"
	RoleExit   Role = "exit"
)

// Spec is relay deployment configuration (JSON file: -spec flag).
type Spec struct {
	// SchemaVersion defaults to 1 when zero (see Validate).
	SchemaVersion int `json:"schema_version"`

	Role        Role   `json:"role"`
	MimicPreset string `json:"mimic_preset"`
	UsersPath   string `json:"users_path"`

	// TunnelTLSProvision documents exit TLS provisioning for operators (optional).
	TunnelTLSProvision TunnelTLSProvision `json:"tunnel_tls_provision,omitempty"`

	ListenAddress string `json:"listen_address"`
	VLESSPort     int    `json:"vless_port"`

	AdminListen string `json:"admin_listen"` // e.g. 127.0.0.1:8443

	// PublicHost is the hostname or IP clients use to reach the bridge.
	PublicHost string `json:"public_host"`

	// DevMode uses cleartext TCP for the public inbound (local testing only).
	DevMode bool `json:"dev_mode"`

	Reality RealitySpec `json:"reality"`

	Exit ExitTunnelSpec `json:"exit"`

	// TLS for splithttp between bridge and exit (server cert on exit).
	SplitHTTPTLS SplitHTTPTLSSpec `json:"splithttp_tls"`

	// SplithttpPath must be identical on bridge and exit (set explicitly in production).
	// If empty, a path is taken from the mimic preset once per config build (fine for single-process tests only).
	SplithttpPath string `json:"splithttp_path"`

	// SplithttpHost is the HTTP Host header for splithttp (bridge→exit). When set, it overrides mimic.Strategy.Host()
	// so bridge and exit agree even if each process would otherwise instantiate the strategy differently.
	SplithttpHost string `json:"splithttp_host,omitempty"`

	// ExitCertPaths are required on the exit node when using TLS on splithttp inbound.
	ExitCertPaths CertPaths `json:"exit_cert"`
}

type RealitySpec struct {
	Dest        string   `json:"dest"`
	ServerNames []string `json:"server_names"`
	PrivateKey  string   `json:"private_key"`
	ShortIDs    []string `json:"short_ids"`
	PublicKey   string   `json:"public_key"`  // public key material for client export
	Fingerprint string   `json:"fingerprint"` // e.g. chrome
	SpiderX     string   `json:"spider_x"`    // optional path obfuscation, default "/"
}

type ExitTunnelSpec struct {
	Address    string `json:"address"`
	Port       int    `json:"port"`
	TunnelUUID string `json:"tunnel_uuid"` // shared tunnel identity bridge→exit
}

type SplitHTTPTLSSpec struct {
	ServerName  string   `json:"server_name"`
	Alpn        []string `json:"alpn"`
	Fingerprint string   `json:"fingerprint"`
}

type CertPaths struct {
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

// LoadSpec reads and validates a JSON spec file.
func LoadSpec(path string) (*Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Spec
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *Spec) Validate() error {
	ver := s.SchemaVersion
	if ver == 0 {
		ver = 1
	}
	if ver != CurrentSpecSchemaVersion {
		return errors.New("config: unsupported schema_version (rebuild ultra-relay or migrate spec)")
	}
	if s.Role != RoleBridge && s.Role != RoleExit {
		return errors.New("config: role must be bridge or exit")
	}
	if s.TunnelTLSProvision != "" {
		allowed := []TunnelTLSProvision{TunnelTLSACME, TunnelTLSUserProv, TunnelTLSSelfSigned}
		if !slices.Contains(allowed, s.TunnelTLSProvision) {
			return errors.New("config: invalid tunnel_tls_provision")
		}
	}
	if s.VLESSPort <= 0 || s.VLESSPort > 65535 {
		return errors.New("config: invalid vless_port")
	}
	if s.ListenAddress == "" {
		s.ListenAddress = "0.0.0.0"
	}
	switch s.Role {
	case RoleBridge:
		if s.UsersPath == "" {
			return errors.New("config: bridge requires users_path")
		}
		if s.PublicHost == "" {
			return errors.New("config: bridge requires public_host for client export")
		}
		if !s.DevMode {
			if s.Reality.PrivateKey == "" || s.Reality.PublicKey == "" {
				return errors.New("config: bridge requires reality.private_key and reality.public_key unless dev_mode")
			}
			if len(s.Reality.ServerNames) == 0 || s.Reality.Dest == "" {
				return errors.New("config: bridge requires reality.dest and reality.server_names unless dev_mode")
			}
		}
		if s.Exit.Address == "" || s.Exit.Port <= 0 || s.Exit.TunnelUUID == "" {
			return errors.New("config: bridge requires exit.address, exit.port, exit.tunnel_uuid")
		}
	case RoleExit:
		if s.Exit.TunnelUUID == "" {
			return errors.New("config: exit requires exit.tunnel_uuid for inbound tunnel")
		}
		if s.ExitCertPaths.CertFile == "" || s.ExitCertPaths.KeyFile == "" {
			return errors.New("config: exit requires exit_cert.cert_file and key_file")
		}
	}
	return nil
}
