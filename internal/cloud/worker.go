package cloud

import (
	"context"
	"log/slog"
	"time"
)

func (s *Service) run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log := s.Log
	if log == nil {
		log = slog.Default()
	}
	lastErrorCode := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := s.Step(ctx)
			if ctx.Err() != nil {
				return
			}
			if err == nil {
				if lastErrorCode != "" {
					log.Info("cloud worker recovered")
					lastErrorCode = ""
				}
				continue
			}
			code := ErrorCode(err)
			if code == lastErrorCode {
				continue
			}
			log.Warn("cloud worker step failed", "code", code)
			lastErrorCode = code
		}
	}
}
