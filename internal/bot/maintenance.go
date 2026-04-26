package bot

import (
	"context"
	"time"
)

const maintenanceInterval = 24 * time.Hour

func (b *Bot) runMaintenance(ctx context.Context) {
	if b.teleRepo == nil {
		return
	}

	b.pruneOnce(ctx)

	t := time.NewTicker(maintenanceInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b.pruneOnce(ctx)
		}
	}
}

func (b *Bot) pruneOnce(ctx context.Context) {
	n, o, s, err := b.teleRepo.PruneMonitoringRetention(ctx)
	if err != nil {
		b.log.Warn("maintenance: prune failed", "err", err)
		return
	}
	if n == 0 && o == 0 && s == 0 {
		return
	}
	b.log.Info("maintenance: pruned", "notifications", n, "ip_observations", o, "leak_signals", s)
}
