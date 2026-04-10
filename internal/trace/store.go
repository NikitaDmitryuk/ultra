package trace

import (
	"sync"
	"time"
)

const (
	ringSize       = 200          // completed sessions kept in memory
	activeTimeout  = 30 * time.Second // stale active sessions are evicted after this
	cleanupInterval = 15 * time.Second
)

// Store captures per-session timelines from xray log events.
// It is safe for concurrent use.
type Store struct {
	mu      sync.Mutex
	active  map[uint32]*Session // sessions still in progress
	ring    [ringSize]*Session  // circular buffer of completed sessions
	ringIdx int                 // next write position in ring
	stop    chan struct{}
}

// NewStore creates a Store and starts its background cleanup goroutine.
// Call Close to stop the goroutine.
func NewStore() *Store {
	s := &Store{
		active: make(map[uint32]*Session),
		stop:   make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

// Close stops the background goroutine.
func (s *Store) Close() {
	close(s.stop)
}

// Append records an event for the given session ID.
// If the session does not exist yet it is created with the event time as StartedAt.
func (s *Store) Append(id uint32, event Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.active[id]
	if !ok {
		sess = &Session{
			ID:        id,
			StartedAt: event.At,
		}
		s.active[id] = sess
	}

	// Populate convenience fields from specific stages.
	switch event.Stage {
	case StageDomainSniffed:
		sess.Destination = event.Detail
	case StageRoutingDecision:
		sess.OutboundTag = event.Detail
		if sess.Destination == "" {
			sess.Destination = event.Detail
		}
	}

	sess.Events = append(sess.Events, event)

	// StageTunnelUp means the outbound connection is established — session is complete.
	if event.Stage == StageTunnelUp || event.Stage == StageWARPDialStart || event.Stage == StageDirectDialStart {
		s.complete(id, sess)
	}
}

// complete moves a session from active to the ring buffer (must be called with mu held).
func (s *Store) complete(id uint32, sess *Session) {
	delete(s.active, id)
	s.ring[s.ringIdx] = sess
	s.ringIdx = (s.ringIdx + 1) % ringSize
}

// Recent returns up to n completed sessions, newest first.
func (s *Store) Recent(n int) []Session {
	if n <= 0 || n > ringSize {
		n = ringSize
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]Session, 0, n)
	// Iterate ring backwards from ringIdx-1 (newest) to collect n entries.
	for i := 0; i < ringSize && len(out) < n; i++ {
		idx := (s.ringIdx - 1 - i + ringSize) % ringSize
		if s.ring[idx] != nil {
			out = append(out, *s.ring[idx])
		}
	}
	return out
}

// Active returns all currently open sessions (useful for debugging stalls).
func (s *Store) Active() []Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]Session, 0, len(s.active))
	for _, sess := range s.active {
		out = append(out, *sess)
	}
	return out
}

// cleanupLoop evicts stale active sessions that never received a terminal event.
func (s *Store) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case now := <-ticker.C:
			s.mu.Lock()
			for id, sess := range s.active {
				if now.Sub(sess.StartedAt) > activeTimeout {
					s.complete(id, sess)
				}
			}
			s.mu.Unlock()
		}
	}
}
