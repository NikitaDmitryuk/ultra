package trace

import "time"

// Stage names emitted by the LogHandler when classifying xray log events.
const (
	StageClientFirstByte = "client_first_byte" // bridge: first bytes received from client
	StageDomainSniffed   = "domain_sniffed"    // bridge: destination domain extracted from TLS/HTTP
	StageRoutingDecision = "routing_decision"  // bridge/exit: outbound tag selected
	StageDialExitStart   = "dial_exit_start"   // bridge: SplitHTTP dial to exit node started
	StageTunnelUp        = "tunnel_up"         // bridge: outbound connection established (data flowing)
	StageWARPDialStart   = "warp_dial_start"   // exit: connecting to destination via WARP SOCKS5
	StageDirectDialStart = "direct_dial_start" // exit: connecting to destination directly (freedom)
)

// Event is a single timestamped step captured from an xray log line.
type Event struct {
	At     time.Time
	Stage  string
	Detail string // destination, outbound tag, address, etc.
}

// Session holds the complete timeline of one xray connection identified by its session ID.
type Session struct {
	ID          uint32
	StartedAt   time.Time
	Destination string // filled from routing_decision or domain_sniffed
	OutboundTag string // filled from routing_decision
	Events      []Event
}

// StageDeltasUS returns, for each Stage seen, the microseconds elapsed since StartedAt.
// Useful for JSON serialisation in the admin API.
func (s *Session) StageDeltasUS() map[string]int64 {
	out := make(map[string]int64, len(s.Events))
	for _, e := range s.Events {
		us := e.At.Sub(s.StartedAt).Microseconds()
		// Keep the first occurrence of each stage (don't overwrite with later ones).
		if _, exists := out[e.Stage]; !exists {
			out[e.Stage] = us
		}
	}
	return out
}
