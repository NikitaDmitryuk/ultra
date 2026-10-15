package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/subscriptionmeta"
)

type SubscriptionQuotaSource interface {
	SubscriptionQuota(context.Context, string, time.Time) (db.PoolQuota, error)
}

func (s *Server) setSubscriptionQuota(ctx context.Context, h http.Header, accountID string, nodes []exits.Node) {
	if s.SubscriptionQuota == nil || accountID == "" {
		return
	}
	groups := s.subscriptionQuotaGroups(ctx, nodes)
	q, err := s.SubscriptionQuota.SubscriptionQuota(ctx, accountID, time.Now().UTC())
	if err == nil && q.Scope == "" {
		return
	}
	if err != nil {
		h.Set("X-Ultra-Quota-State", "unknown")
		subscriptionmeta.Announce(h, "Общая квота выходов сейчас неизвестна."+groups)
		return
	}
	scope := q.Scope
	if scope == "vultr" {
		scope = "shared"
	}
	h.Set("X-Ultra-Quota-Scope", scope)
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
	subscriptionmeta.Announce(
		h,
		fmt.Sprintf("Общая квота: осталось %.2f ГиБ. Данные: %s (%s).%s", float64(q.Remaining)/(1<<30), observed, q.State, groups),
	)
}

func (s *Server) exitQuotaKinds(ctx context.Context) map[string]string {
	kinds := map[string]string{}
	if s.Members == nil || s.Members.Repo == nil {
		return kinds
	}
	budgets, err := s.Members.Repo.Budgets(ctx)
	if err != nil {
		return kinds
	}
	return classifyExitQuotaKinds(budgets)
}

func classifyExitQuotaKinds(budgets []db.ExitBudget) map[string]string {
	kinds := map[string]string{}
	for _, budget := range budgets {
		kind := "separate"
		if budget.Source == "vultr" {
			kind = "shared"
		}
		kinds[budget.ID] = kind
	}
	return kinds
}

func (s *Server) subscriptionQuotaGroups(ctx context.Context, nodes []exits.Node) string {
	return subscriptionQuotaGroupText(nodes, s.exitQuotaKinds(ctx))
}

func subscriptionQuotaGroupText(nodes []exits.Node, kinds map[string]string) string {
	if len(kinds) == 0 {
		return ""
	}
	shared, separate := []string{}, []string{}
	seenShared, seenSeparate := map[string]bool{}, map[string]bool{}
	for _, node := range nodes {
		name := subscriptionCountryName(node)
		if name == "" {
			continue
		}
		switch kinds[node.ID] {
		case "shared":
			if !seenShared[name] {
				shared, seenShared[name] = append(shared, name), true
			}
		case "separate":
			if !seenSeparate[name] {
				separate, seenSeparate[name] = append(separate, name), true
			}
		}
	}
	parts := []string{}
	if len(shared) > 0 {
		parts = append(parts, "Общая квота: "+strings.Join(shared, ", ")+".")
	}
	if len(separate) > 0 {
		parts = append(parts, "Отдельная квота: "+strings.Join(separate, ", ")+".")
	}
	if len(parts) == 0 {
		return ""
	}
	return " " + strings.Join(parts, " ")
}
