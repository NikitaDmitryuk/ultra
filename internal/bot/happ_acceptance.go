package bot

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"
)

// Acceptance only changes ports in an already authorised, uncached admin
// preview. It cannot change UUIDs, endpoints, quotas, or ordinary subscriptions.
type happAcceptance struct {
	TokenDigest string    `json:"token_digest"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	PrimaryPort int       `json:"primary_port"`
	ReservePort int       `json:"reserve_port"`
}

// The private, expiring token selection also allows normal subscription refresh
// to identify the app. Browser previews alone cannot establish its User-Agent.
func (b *Bot) captureHappAcceptanceUserAgent(ua string) {
	if b.log == nil {
		return
	}
	for {
		n := b.happAcceptanceUACount.Load()
		if n >= 8 {
			return
		}
		if b.happAcceptanceUACount.CompareAndSwap(n, n+1) {
			break
		}
	}
	if len(ua) > 256 {
		ua = ua[:256]
	}
	b.log.Info("happ acceptance client", "user_agent", ua)
}

func loadHappAcceptance(path, token string, now time.Time) (*happAcceptance, error) {
	invalid := errors.New("acceptance unavailable")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
		return nil, invalid
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, invalid
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, invalid
	}
	var c happAcceptance
	data, readErr := io.ReadAll(io.LimitReader(f, 4097))
	if readErr != nil || json.Unmarshal(data, &c) != nil {
		return nil, invalid
	}
	digest, err := hex.DecodeString(c.TokenDigest)
	expected := sha256.Sum256([]byte(token))
	if err != nil || subtle.ConstantTimeCompare(digest, expected[:]) != 1 || c.IssuedAt.After(now) || !c.ExpiresAt.After(now) ||
		c.ExpiresAt.Sub(c.IssuedAt) > time.Hour ||
		!c.ExpiresAt.After(c.IssuedAt) ||
		c.PrimaryPort < 1024 ||
		c.PrimaryPort > 65535 ||
		c.ReservePort < 1024 ||
		c.ReservePort > 65535 ||
		c.PrimaryPort == c.ReservePort {
		return nil, invalid
	}
	return &c, nil
}

func (c *happAcceptance) rewrite(body []byte) ([]byte, error) {
	var profiles []map[string]any
	if json.Unmarshal(body, &profiles) != nil || len(profiles) == 0 {
		return nil, errors.New("invalid profiles")
	}
	for _, profile := range profiles {
		outbounds, ok := profile["outbounds"].([]any)
		if !ok {
			return nil, errors.New("invalid outbounds")
		}
		primary, reserve := 0, 0
		for _, value := range outbounds {
			out, ok := value.(map[string]any)
			if !ok || out["protocol"] == "freedom" {
				return nil, errors.New("unsafe outbound")
			}
			if out["protocol"] != "vless" {
				continue
			}
			stream, ok := out["streamSettings"].(map[string]any)
			if !ok {
				return nil, errors.New("invalid transport")
			}
			port := 0
			switch stream["security"] {
			case "tls":
				if stream["network"] != "xhttp" {
					return nil, errors.New("invalid primary")
				}
				port = c.PrimaryPort
				primary++
			case "reality":
				port = c.ReservePort
				reserve++
			default:
				return nil, errors.New("invalid security")
			}
			settings, ok := out["settings"].(map[string]any)
			if !ok {
				return nil, errors.New("invalid settings")
			}
			next, ok := settings["vnext"].([]any)
			if !ok || len(next) != 1 {
				return nil, errors.New("invalid destinations")
			}
			destination, ok := next[0].(map[string]any)
			if !ok {
				return nil, errors.New("invalid destination")
			}
			destination["port"] = port
		}
		if primary != 1 || reserve != 1 {
			return nil, errors.New("both transports required")
		}
		if name, ok := profile["remarks"].(string); ok {
			profile["remarks"] = "Приёмка переключения · " + name
		}
	}
	return json.Marshal(profiles)
}
