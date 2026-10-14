package deployansible

import (
	"errors"
	"net"
	"path/filepath"
	"regexp"
)

// ReplicaRequest is a fixed, validated controller operation, never caller-supplied
// inventory. Credential sources are passed as descriptors by the submitting UID.
// The controller writes its own bridge-local inventory and pinned remote target.
type ReplicaRequest struct {
	ID            string `json:"id"`
	Host          string `json:"host"`
	Identity      string `json:"identity"`
	KnownHosts    string `json:"known_hosts"`
	User          string `json:"user"`
	Password      string `json:"password"`
	PrimaryPort   int    `json:"primary_port"`
	Architecture  string `json:"architecture"`
	RequiredBytes int64  `json:"required_bytes"`
	Connections   int    `json:"connections"`
	Workers       int    `json:"workers"`
	Prepared      int    `json:"prepared"`
	Locks         int    `json:"locks"`
	Senders       int    `json:"senders"`
}

func (r ReplicaRequest) ValidatePolicy() error {
	if !regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`).MatchString(r.ID) || net.ParseIP(r.Host) == nil {
		return errors.New("invalid replica target")
	}
	if !filepath.IsAbs(r.Identity) || !filepath.IsAbs(r.KnownHosts) || !regexp.MustCompile(`^[a-z_][a-z0-9_]*$`).MatchString(r.User) || !regexp.MustCompile(`^[a-f0-9]{48,128}$`).MatchString(r.Password) {
		return errors.New("invalid replica credentials")
	}
	if r.PrimaryPort < 1 || r.PrimaryPort > 65535 || (r.Architecture != "x86_64" && r.Architecture != "aarch64") || r.RequiredBytes < 5<<30 || r.Connections < 1 || r.Workers < 0 || r.Prepared < 0 || r.Locks < 1 || r.Senders < 1 {
		return errors.New("invalid replica sizing")
	}
	return nil
}
