package proxy

import (
	"fmt"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"google.golang.org/protobuf/proto"
)

// healthRoutingCandidate permits only a rule replacement. The pinned router
// publishes rules atomically, but does not update domainStrategy, and publishes
// balancers separately. Keep those paths on the full core lifecycle.
func healthRoutingCandidate(previous, next *core.Config) *router.Config {
	if previous == nil || next == nil || hasGRPCOutbound(next) {
		return nil
	}
	before, after := proto.Clone(previous).(*core.Config), proto.Clone(next).(*core.Config)
	var oldRouting, newRouting *router.Config
	for _, item := range []struct {
		config  *core.Config
		routing **router.Config
	}{{before, &oldRouting}, {after, &newRouting}} {
		for i, app := range item.config.App {
			if app.Type != serial.GetMessageType(new(router.Config)) {
				continue
			}
			if *item.routing != nil {
				return nil
			}
			value, err := app.GetInstance()
			if err != nil {
				return nil
			}
			*item.routing = value.(*router.Config)
			// Work on cloned messages; neither running nor candidate config changes.
			item.config.App[i] = &serial.TypedMessage{Type: app.Type}
		}
	}
	if oldRouting == nil || newRouting == nil || !proto.Equal(before, after) ||
		oldRouting.DomainStrategy != newRouting.DomainStrategy ||
		len(oldRouting.BalancingRule) != 0 || len(newRouting.BalancingRule) != 0 {
		return nil
	}
	oldSettings, newSettings := proto.Clone(oldRouting).(*router.Config), proto.Clone(newRouting).(*router.Config)
	oldSettings.Rule, newSettings.Rule = nil, nil
	if !proto.Equal(oldSettings, newSettings) {
		return nil
	}
	return newRouting
}

// The pinned gRPC dialer caches a ClientConn whose reconnect dialer captures the
// first stream's context (grpc/dial.go:getGrpcClient). After that context is
// canceled, an exit restart can leave the preserved outbound unable to reconnect.
// Retain full reload for gRPC until the upstream lifecycle is fixed.
func hasGRPCOutbound(cfg *core.Config) bool {
	for _, outbound := range cfg.Outbound {
		if outbound.SenderSettings == nil {
			continue
		}
		value, err := outbound.SenderSettings.GetInstance()
		if err != nil {
			return true
		}
		sender, ok := value.(*proxyman.SenderConfig)
		if !ok {
			return true
		}
		if sender.StreamSettings == nil {
			continue
		}
		stream := sender.StreamSettings
		if stream.ProtocolName == "grpc" || stream.ProtocolName == "gun" {
			return true
		}
		for _, settings := range stream.TransportSettings {
			if settings.ProtocolName == "grpc" || settings.ProtocolName == "gun" {
				return true
			}
		}
	}
	return false
}

// reloadHealthRouting runs under Runner.mu. Existing streams retain their
// selected outbound; new streams see the replacement rules. Administrative
// changes never enter this path, so full reload still terminates revoked flows.
func (r *Runner) reloadHealthRouting(cfg *core.Config) (bool, error) {
	candidate := healthRoutingCandidate(r.config, cfg)
	if candidate == nil {
		return false, nil
	}
	active, ok := r.inst.GetFeature(routing.RouterType()).(*router.Router)
	if !ok {
		return false, nil
	}
	// Do not construct a temporary core: core.New replaces process-global log
	// and system-dialer state, and closing it does not restore the active core.
	// Non-routing settings already match; AddRule validates the changed rules.
	// ReloadRules builds every rule before its atomic store. A validation failure
	// leaves the active rule set and the confirmed configuration untouched.
	if err := active.AddRule(serial.ToTypedMessage(candidate), false); err != nil {
		return false, fmt.Errorf("replace health routing: %w", err)
	}
	r.config = cfg
	r.status.RoutingCount++
	r.status.RoutingAt = time.Now().UTC()
	r.status.Error = ""
	return true, nil
}
