//go:build !linux

package firewall

import "context"

type noop struct{}

func newManager() Manager { return noop{} }

func (noop) OpenPort(_ context.Context, _ int) error  { return nil }
func (noop) ClosePort(_ context.Context, _ int) error { return nil }
