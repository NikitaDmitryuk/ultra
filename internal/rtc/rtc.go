// Package rtc defines the optional, per-device olcRTC ingress contract.
package rtc

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// SourceCommit is the reviewed upstream source; do not deploy mutable latest builds.
const SourceCommit = "189d16c093c4f721376afb5eaa0213d132a11242"

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)

type Binding struct {
	ID           string `json:"id"`
	UserUUID     string `json:"user_uuid"`
	Enabled      bool   `json:"enabled"`
	Provider     string `json:"provider"`
	RoomID       string `json:"room_id"`
	Transport    string `json:"transport"`
	ListenPort   int    `json:"listen_port"`
	KeyFile      string `json:"key_file"`
	PasswordFile string `json:"password_file"`
	// BootstrapDNS resolves conference infrastructure before the tunnel exists.
	BootstrapDNS string `json:"bootstrap_dns"`
}

func Validate(bindings []Binding) error {
	ids, ports, files, rooms := map[string]bool{}, map[int]bool{}, map[string]bool{}, map[string]bool{}
	for _, b := range bindings {
		id, err := uuid.Parse(b.UserUUID)
		if !idPattern.MatchString(b.ID) || err != nil || id.String() != b.UserUUID {
			return errors.New("rtc: invalid id or canonical user_uuid")
		}
		if ids[b.ID] || ports[b.ListenPort] {
			return errors.New("rtc: duplicate id or listen_port")
		}
		ids[b.ID], ports[b.ListenPort] = true, true
		if b.ListenPort < 1024 || b.ListenPort > 65535 {
			return errors.New("rtc: listen_port must be 1024..65535")
		}
		if b.Provider != "wbstream" && b.Provider != "telemost" {
			return errors.New("rtc: provider must be wbstream or telemost")
		}
		if b.Transport != "vp8channel" {
			return errors.New("rtc: pilot requires vp8channel")
		}
		if b.RoomID == "" || len(b.RoomID) > 2048 || strings.ContainsAny(b.RoomID, "\r\n\t @#$<>") {
			return errors.New("rtc: invalid room_id (use the service room ID without URI delimiters)")
		}
		room := b.Provider + ":" + b.RoomID
		if rooms[room] {
			return errors.New("rtc: each binding requires a separate room")
		}
		rooms[room] = true
		host, port, err := net.SplitHostPort(b.BootstrapDNS)
		if err != nil || net.ParseIP(host) == nil || port != "53" {
			return errors.New("rtc: bootstrap_dns must be a reachable DNS IP:53")
		}
		for _, p := range []string{b.KeyFile, b.PasswordFile} {
			if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, "\r\n\x00") || files[p] {
				return errors.New("rtc: secret paths must be unique absolute clean paths")
			}
			files[p] = true
		}
	}
	return nil
}

// Tag encodes the owner in a server-controlled inbound tag. Clients cannot set it.
func (b Binding) Tag() string { return "rtc-" + b.UserUUID + "-" + b.ID }
func UserFromTag(tag string) string {
	if len(tag) < 42 || !strings.HasPrefix(tag, "rtc-") || tag[40] != '-' {
		return ""
	}
	id := tag[4:40]
	u, e := uuid.Parse(id)
	if e != nil || u.String() != id || !idPattern.MatchString(tag[41:]) {
		return ""
	}
	return id
}

// ReadSecret avoids reflecting paths or contents into API/log errors.
func ReadSecret(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("rtc: secret unavailable")
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0007 != 0 {
		return "", errors.New("rtc: secret must be a private regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, 130))
	s := strings.TrimSpace(string(data))
	decoded, e := hex.DecodeString(s)
	if err != nil || e != nil || len(decoded) != 32 {
		return "", errors.New("rtc: invalid secret")
	}
	return s, nil
}

func Subscription(bindings []Binding, user string) (string, error) {
	if err := Validate(bindings); err != nil {
		return "", err
	}
	lines := []string{"#name: ultra RTC", "#refresh: 1h"}
	for _, b := range bindings {
		if !b.Enabled || b.UserUUID != user {
			continue
		}
		key, err := ReadSecret(b.KeyFile)
		if err != nil {
			return "", err
		}
		lines = append(lines, fmt.Sprintf("olcrtc://%s?vp8channel<vp8-fps=30&vp8-batch=64>@%s#%s$%s", b.Provider, b.RoomID, key, b.ID))
	}
	if len(lines) == 2 {
		return "", errors.New("rtc: no active bindings")
	}
	return strings.Join(lines, "\n") + "\n", nil
}
