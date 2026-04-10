// Package stats polls the in-process Xray stats API and persists traffic deltas to PostgreSQL.
package stats

import (
	"context"
	"log/slog"
	"time"

	xraystats "github.com/xtls/xray-core/features/stats"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/db"
)

// XrayInstance is the subset of proxy.Runner used by the collector.
// Declared as an interface to keep the stats package decoupled from proxy.
type XrayInstance interface {
	// GetStatsManager returns the Xray stats.Manager feature, or nil if stats are not enabled.
	GetStatsManager() xraystats.Manager
}

// TrafficDB is the subset of db.TrafficRepo used by the collector.
type TrafficDB interface {
	RecordSamples(ctx context.Context, samples []db.TrafficSample) error
	PruneOldSamples(ctx context.Context, retention time.Duration) (int64, error)
}

// SampleRetention is how long raw traffic_stats rows are kept before pruning.
// Monthly aggregates in monthly_traffic are unaffected and kept indefinitely.
const SampleRetention = 60 * 24 * time.Hour // 60 days

// UserLister provides the current active user list.
type UserLister interface {
	List() []auth.User
}

// Collector periodically reads per-user traffic counters from Xray and writes deltas to DB.
type Collector struct {
	xray     XrayInstance
	traffic  TrafficDB
	users    UserLister
	interval time.Duration
	log      *slog.Logger

	stop chan struct{}
	done chan struct{}
}

// New creates a Collector. interval is how often to poll (minimum 10 s).
func New(xray XrayInstance, traffic TrafficDB, users UserLister, interval time.Duration, log *slog.Logger) *Collector {
	if interval < 10*time.Second {
		interval = 60 * time.Second
	}
	if log == nil {
		log = slog.Default()
	}
	return &Collector{
		xray:     xray,
		traffic:  traffic,
		users:    users,
		interval: interval,
		log:      log,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// Start launches the background collection loop.
func (c *Collector) Start() {
	go c.loop()
}

// Close stops the collection loop and waits for it to finish.
func (c *Collector) Close() {
	close(c.stop)
	<-c.done
}

func (c *Collector) loop() {
	defer close(c.done)
	t := time.NewTicker(c.interval)
	defer t.Stop()
	prune := time.NewTicker(24 * time.Hour)
	defer prune.Stop()
	// Prune once on startup so stale rows are removed immediately after a long downtime.
	c.prune()
	for {
		select {
		case <-c.stop:
			return
		case now := <-t.C:
			c.collect(now)
		case <-prune.C:
			c.prune()
		}
	}
}

func (c *Collector) prune() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n, err := c.traffic.PruneOldSamples(ctx, SampleRetention)
	if err != nil {
		c.log.Warn("stats: prune old samples failed", "err", err)
		return
	}
	if n > 0 {
		c.log.Info("stats: pruned old traffic samples", "deleted", n, "retention_days", int(SampleRetention.Hours()/24))
	}
}

// collect reads Xray traffic counters for every active user, resets them to zero (delta model),
// and writes non-zero samples to the database.
func (c *Collector) collect(at time.Time) {
	sm := c.xray.GetStatsManager()
	if sm == nil {
		return
	}

	users := c.users.List()
	samples := make([]db.TrafficSample, 0, len(users))

	for _, u := range users {
		if u.UUID == "" {
			continue
		}
		upKey := "user>>>" + u.UUID + ">>>traffic>>>uplink"
		downKey := "user>>>" + u.UUID + ">>>traffic>>>downlink"

		var upBytes, downBytes int64
		if cnt := sm.GetCounter(upKey); cnt != nil {
			upBytes = cnt.Set(0) // atomic swap: read current value and reset to 0
		}
		if cnt := sm.GetCounter(downKey); cnt != nil {
			downBytes = cnt.Set(0)
		}

		samples = append(samples, db.TrafficSample{
			UserUUID:      u.UUID,
			CollectedAt:   at,
			UplinkBytes:   upBytes,
			DownlinkBytes: downBytes,
		})
	}

	if len(samples) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := c.traffic.RecordSamples(ctx, samples); err != nil {
		c.log.Warn("stats: failed to record traffic samples", "err", err)
	}
}
