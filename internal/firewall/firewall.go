package firewall

import "context"

// Manager opens/closes host firewall ports for per-client SOCKS inbounds (best-effort).
type Manager interface {
	OpenPort(ctx context.Context, port int) error
	ClosePort(ctx context.Context, port int) error
}

// New returns the platform-specific implementation (no-op on non-Linux).
func New() Manager { return newManager() }
