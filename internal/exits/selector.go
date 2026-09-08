package exits

import (
	"context"
	"sync"
	"time"
)

const defaultProbeInterval = 10 * time.Second

type streak struct {
	failures, successes int
	since               time.Time
	available           bool
}

// Selector separates raw measurements from routing eligibility. Probe must honor ctx.
type Selector struct {
	mu       sync.RWMutex
	cycle    sync.Mutex
	activeID string
	health   map[string]Health
	streaks  map[string]streak
	probe    func(context.Context, Node) Health
	now      func() time.Time
}

func NewSelector(check func(context.Context, Node) Health) *Selector {
	return &Selector{health: make(map[string]Health), streaks: make(map[string]streak), probe: check, now: time.Now}
}
func (s *Selector) ActiveID() string      { s.mu.RLock(); defer s.mu.RUnlock(); return s.activeID }
func (s *Selector) SetActiveID(id string) { s.mu.Lock(); defer s.mu.Unlock(); s.activeID = id }
func (s *Selector) HealthSnapshot() map[string]Health {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]Health, len(s.health))
	for id, h := range s.health {
		h.Checks = append([]ProbeResult(nil), h.Checks...)
		out[id] = h
	}
	return out
}

// ProbeAndSelect returns changed only for eligibility or active-route changes.
func (s *Selector) ProbeAndSelect(ctx context.Context, nodes []Node) (Node, bool) {
	s.cycle.Lock()
	defer s.cycle.Unlock()
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	enabled := FilterEnabled(nodes)
	results := make([]Health, len(enabled))
	var wg sync.WaitGroup
	slots := make(chan struct{}, 4)
	for i, n := range enabled {
		wg.Add(1)
		go func(i int, n Node) {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				return
			}
			if s.probe != nil {
				results[i] = s.probe(ctx, n)
			}
		}(i, n)
	}
	wg.Wait()
	// Cancellation by shutdown or the caller is not evidence of a network failure.
	if parent.Err() != nil {
		return Node{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	eligible := map[string]bool{}
	health := map[string]Health{}
	changed := false
	for i, n := range enabled {
		h := results[i]
		h.ID = n.ID
		h.CheckedAt = now
		st, known := s.streaks[n.ID]
		previous := s.health[n.ID]
		// Preserve issued routes at startup until two measured failures, then require recovery.
		if !known {
			st.available = true
			previous.PreferredReady = true
		}
		if h.InternetOK {
			st.failures = 0
			st.successes++
			if st.since.IsZero() {
				st.since = now
			}
			if st.successes >= 3 {
				st.available = true
			}
		} else {
			st.successes = 0
			st.failures++
			st.since = time.Time{}
			if st.failures >= 2 {
				st.available = false
			}
		}
		h.Eligible = st.available
		// A recovered preferred exit must remain stable before users return to it.
		h.PreferredReady = st.available && (previous.PreferredReady || (!st.since.IsZero() && now.Sub(st.since) >= 60*time.Second))
		if prev, ok := s.health[n.ID]; !ok || prev.Eligible != h.Eligible || prev.PreferredReady != h.PreferredReady {
			changed = true
		}
		s.streaks[n.ID] = st
		eligible[n.ID] = h.Eligible
		health[n.ID] = h
	}
	candidate, ok := SelectActive(enabled, eligible)
	if !ok {
		for _, n := range enabled {
			if n.ID == s.activeID {
				candidate = n
				break
			}
		}
	}
	if ok && eligible[s.activeID] && candidate.ID != s.activeID && !health[candidate.ID].PreferredReady {
		for _, n := range enabled {
			if n.ID == s.activeID {
				candidate = n
				break
			}
		}
	}
	if candidate.ID != s.activeID || len(health) != len(s.health) {
		changed = true
	}
	s.activeID = candidate.ID
	for id, h := range health {
		h.Active = id == s.activeID
		health[id] = h
	}
	s.health = health
	for id := range s.streaks {
		if _, ok := health[id]; !ok {
			delete(s.streaks, id)
		}
	}
	return candidate, changed
}

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
