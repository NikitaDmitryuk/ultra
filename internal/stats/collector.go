// Package stats polls the in-process Xray stats API and persists traffic deltas to PostgreSQL.
package stats

import (
	"context"
	"errors"
	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
	"github.com/google/uuid"
	"log/slog"
	"strings"
	"sync"
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

	state       *runtimestate.Store
	mu          sync.Mutex
	pending     *runtimestate.TrafficBatch
	pendingFull bool
	replayMu    sync.Mutex
	stop        chan struct{}
	done        chan struct{}
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
	if c.state != nil {
		workerDone := make(chan struct{})
		go func() { defer close(workerDone); c.replayLoop() }()
		defer func() { <-workerDone }()
	}
	t := time.NewTicker(c.interval)
	defer t.Stop()
	prune := time.NewTicker(24 * time.Hour)
	defer prune.Stop()
	// Prune once on startup so stale rows are removed immediately after a long downtime.
	if c.state == nil {
		c.prune()
	}
	for {
		select {
		case <-c.stop:
			if c.state != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_ = c.Checkpoint(ctx)
				cancel()
			}
			return
		case now := <-t.C:
			if c.state != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				if err := c.Checkpoint(ctx); err != nil {
					c.log.Warn("stats: checkpoint failed", "err", err)
				}

				cancel()
			} else {
				c.collect(now)
			}
		case <-prune.C:
			if c.state == nil {
				c.prune()
			}
		}
	}
}

func (c *Collector) prune() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c.mu.Lock()
	traffic := c.traffic
	c.mu.Unlock()
	if traffic == nil {
		return
	}
	n, err := traffic.PruneOldSamples(ctx, SampleRetention)
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
	if all, ok := c.users.(interface{ ListAll() []auth.User }); ok {
		users = all.ListAll()
	}
	var measured map[string]map[string][2]int64
	meter, hasMeter := c.xray.(interface {
		DrainRouteTraffic() map[string]map[string][2]int64
	})
	if hasMeter {
		measured = meter.DrainRouteTraffic()
	}
	samples := make([]db.TrafficSample, 0, len(users))

	for _, u := range users {
		if u.UUID == "" || (u.Kind != "" && u.Kind != "vless") {
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

		for _, route := range u.Routes {
			if cnt := sm.GetCounter("user>>>" + route.UUID + ">>>traffic>>>uplink"); cnt != nil {
				upBytes += cnt.Set(0)
			}
			if cnt := sm.GetCounter("user>>>" + route.UUID + ">>>traffic>>>downlink"); cnt != nil {
				downBytes += cnt.Set(0)
			}
		}
		if hasMeter {
			credentials := []string{u.UUID}
			for _, route := range u.Routes {
				credentials = append(credentials, route.UUID)
			}
			for _, credential := range credentials {
				for tag, bytes := range measured[credential] {
					samples = append(samples, db.TrafficSample{UserUUID: u.UUID, CollectedAt: at, UplinkBytes: bytes[0], DownlinkBytes: bytes[1], ExitTag: tag})
				}
			}
			continue
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

// NewDurable checkpoints independently of PostgreSQL availability every five seconds.
func NewDurable(xray XrayInstance, traffic TrafficDB, users UserLister, state *runtimestate.Store, log *slog.Logger) *Collector {
	c := New(xray, traffic, users, time.Minute, log)
	c.interval = 5 * time.Second
	c.state = state
	return c
}
func (c *Collector) SetTrafficDB(traffic TrafficDB) { c.mu.Lock(); c.traffic = traffic; c.mu.Unlock() }

// Checkpoint retains a drained batch in memory on a disk error; it never drains twice.
func (c *Collector) Checkpoint(ctx context.Context) error     { return c.checkpoint(ctx, false) }
func (c *Collector) CheckpointFull(ctx context.Context) error { return c.checkpoint(ctx, true) }
func (c *Collector) checkpoint(ctx context.Context, full bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == nil {
		return errors.New("durable store unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.pending != nil {
		appendPending := c.state.AppendBatch
		if c.pendingFull {
			appendPending = c.state.AppendBatchFull
		}
		if err := appendPending(*c.pending); err != nil {
			return err
		}
		c.pending = nil
		c.pendingFull = false
	}
	meter, ok := c.xray.(interface {
		DrainAccountTraffic() map[string]map[string][2]int64
	})
	if !ok {
		return errors.New("route traffic meter required")
	}
	at := time.Now().UTC()
	batch := runtimestate.TrafficBatch{Version: 1, NodeID: c.state.NodeID(), BatchID: uuid.NewString(), CollectedAt: at}
	for account, tags := range meter.DrainAccountTraffic() {
		for tag, n := range tags {
			batch.Samples = append(batch.Samples, runtimestate.Sample{AccountID: account, ExitID: strings.TrimPrefix(tag, "to-exit-"), ExitTag: tag, Period: at.Format("2006-01"), UplinkBytes: n[0], DownlinkBytes: n[1]})
		}
	}
	// Empty measurement still flushes conservative durable reservations after a crash.
	appendBatch := c.state.AppendBatch
	if full {
		appendBatch = c.state.AppendBatchFull
	}
	if err := appendBatch(batch); err != nil {
		c.pending = &batch
		c.pendingFull = full
		return err
	}
	return nil
}
func (c *Collector) Replay(ctx context.Context) error {
	c.replayMu.Lock()
	defer c.replayMu.Unlock()
	c.mu.Lock()
	traffic := c.traffic
	c.mu.Unlock()
	if traffic == nil {
		return errors.New("traffic database unavailable")
	}
	durable, ok := traffic.(interface {
		RecordBatch(context.Context, runtimestate.TrafficBatch) error
	})
	if !ok {
		return errors.New("traffic database lacks batch support")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		batches, err := c.state.PendingBatches(64)
		if err != nil {
			return err
		}
		if len(batches) == 0 {
			return nil
		}
		for _, b := range batches {
			if err = durable.RecordBatch(ctx, b); err != nil {
				return err
			}
			if err = c.state.AckBatch(b.BatchID); err != nil {
				return err
			}
		}
	}
}
func (c *Collector) replayLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	prune := time.NewTicker(24 * time.Hour)
	defer prune.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := c.Replay(ctx)
			cancel()
			if err != nil {
				c.log.Warn("stats: replay deferred", "err", err)
			}
		case <-prune.C:
			c.prune()
		}
	}
}
