package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/NikitaDmitryuk/ultra/internal/subscriptionmeta"
)

type SubscriptionQuotaSource interface {
	SubscriptionQuota(context.Context, string, time.Time) (db.PoolQuota, error)
}

func (s *Server) setSubscriptionQuota(ctx context.Context, h http.Header, accountID string) {
	if s.SubscriptionQuota == nil || accountID == "" {
		return
	}
	q, err := s.SubscriptionQuota.SubscriptionQuota(ctx, accountID, time.Now().UTC())
	if err == nil && q.Scope == "" {
		return
	}
	if err != nil {
		h.Set("X-Ultra-Quota-State", "unknown")
		subscriptionmeta.Announce(h, "Vultr: общий пользовательский лимит сейчас неизвестен. Остальные выходы учитываются отдельно.")
		return
	}
	h.Set("X-Ultra-Quota-Scope", q.Scope)
	h.Set("X-Ultra-Quota-Period", q.Period)
	h.Set("X-Ultra-Quota-State", q.State)
	if q.ObservedAt != nil {
		h.Set("X-Ultra-Quota-Observed-At", q.ObservedAt.UTC().Format(time.RFC3339))
	}
	if !q.ResetsAt.IsZero() {
		h.Set("X-Ultra-Quota-Resets-At", q.ResetsAt.UTC().Format(time.RFC3339))
	}
	// A missing observation or nonpositive allowance is not an unlimited quota.
	// Omit standard counters rather than showing unknown values as zero/unlimited.
	if q.ObservedAt != nil && q.PersonalLimit > 0 && q.Used >= 0 {
		h.Set("subscription-userinfo", fmt.Sprintf("upload=0; download=%d; total=%d", q.Used, q.PersonalLimit))
	}
	observed := "нет подтверждённого измерения"
	if q.ObservedAt != nil {
		observed = q.ObservedAt.UTC().Format(time.RFC3339)
	}
	subscriptionmeta.Announce(h, fmt.Sprintf("Vultr: остаток %.2f ГиБ, общий личный лимит; остальные выходы отдельно. Данные: %s (%s).", float64(q.Remaining)/(1<<30), observed, q.State))
}
