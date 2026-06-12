package exits

import (
	"context"
	"reflect"
	"sync"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/probe"
)

// healthProbeListen matches config.HealthProbeListenIPPort (bridge dokodemo-door).
const healthProbeListen = "127.0.0.1:11800"

const defaultProbeInterval = 30 * time.Second

// Selector tracks exit health and picks the active node by priority among reachable exits.
type Selector struct {
	mu             sync.RWMutex
	activeID       string
	health         map[string]Health
	onActiveChange func(prevID, nextID string)
}

func NewSelector(onActiveChange func(prevID, nextID string)) *Selector {
	return &Selector{
		health:         make(map[string]Health),
		onActiveChange: onActiveChange,
	}
}

func (s *Selector) ActiveID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeID
}

func (s *Selector) SetActiveID(id string) {
	s.mu.Lock()
	s.activeID = id
	s.mu.Unlock()
}

func (s *Selector) HealthSnapshot() map[string]Health {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]Health, len(s.health))
	for k, v := range s.health {
		out[k] = v
	}
	return out
}

// ProbeAndSelect probes enabled exits and updates active selection.
func (s *Selector) ProbeAndSelect(ctx context.Context, nodes []Node) (active Node, changed bool) {
	enabled := FilterEnabled(nodes)
	reachable := make(map[string]bool, len(enabled))
	health := make(map[string]Health, len(enabled))

	for _, n := range enabled {
		h := Health{ID: n.ID}
		rtt, err := probe.DialTCP(ctx, n.DialAddr())
		if err == nil {
			h.Reachable = true
			h.TunnelLatencyMS = rtt.Milliseconds()
			reachable[n.ID] = true
		}
		health[n.ID] = h
	}

	candidate, _ := SelectActive(enabled, reachable)

	s.mu.RLock()
	prevID := s.activeID
	prevHealth := s.health
	s.mu.RUnlock()

	if candidate.ID != "" && reachable[candidate.ID] {
		rtt, err := probe.DialTCP(ctx, healthProbeListen)
		if err == nil {
			h := health[candidate.ID]
			h.InternetOK = true
			h.InternetLatencyMS = rtt.Milliseconds()
			health[candidate.ID] = h
		}
	}

	s.mu.Lock()
	healthChanged := !reflect.DeepEqual(prevHealth, health)
	changed = prevID != candidate.ID || healthChanged
	s.activeID = candidate.ID
	for id, h := range health {
		h.Active = id == candidate.ID
	}
	s.health = health
	s.mu.Unlock()

	if changed && s.onActiveChange != nil {
		s.onActiveChange(prevID, candidate.ID)
	}
	return candidate, changed
}

// RunWorker periodically probes exits and invokes onChange when active exit changes.
func (s *Selector) RunWorker(ctx context.Context, interval time.Duration, list func(context.Context) ([]Node, error), onChange func()) {
	if interval <= 0 {
		interval = defaultProbeInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			nodes, err := list(ctx)
			if err != nil {
				continue
			}
			_, changed := s.ProbeAndSelect(ctx, nodes)
			if changed && onChange != nil {
				onChange()
			}
		}
	}
}
