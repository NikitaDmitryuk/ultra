package db

import (
	"context"
	"errors"
	"net/netip"

	"github.com/jackc/pgx/v5"
)

type StaticBudget struct {
	MonthlyBytes int64 `json:"monthly_bytes"`
	Fallback     bool  `json:"is_fallback"`
}

type StaticBudgetNode struct {
	Address string        `json:"address"`
	Budget  *StaticBudget `json:"budget,omitempty"`
}

// EnsureStaticBudgets initializes explicit operator budgets, never observations
// or usage. Adoption without a budget requires an existing authoritative row.
func (r *QuotaRepo) EnsureStaticBudgets(ctx context.Context, nodes []StaticBudgetNode) error {
	if len(nodes) == 0 {
		return errors.New("static nodes required")
	}
	seen := map[string]bool{}
	for _, node := range nodes {
		address, err := netip.ParseAddr(node.Address)
		if err != nil || address.String() != node.Address || seen[node.Address] || (node.Budget != nil && node.Budget.MonthlyBytes <= 0) {
			return errors.New("invalid static budget input")
		}
		seen[node.Address] = true
	}
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(817365009)`); err != nil {
		return err
	}
	for _, node := range nodes {
		rows, err := tx.Query(ctx, `SELECT id::text FROM exit_nodes WHERE enabled AND address=$1 FOR UPDATE`, node.Address)
		if err != nil {
			return err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		if len(ids) != 1 {
			return errors.New("static exit must resolve uniquely")
		}
		var monthly int64
		var source string
		var fallback bool
		err = tx.QueryRow(ctx, `SELECT monthly_bytes,source,is_fallback FROM exit_traffic_budgets WHERE exit_id=$1 FOR UPDATE`, ids[0]).Scan(&monthly, &source, &fallback)
		if errors.Is(err, pgx.ErrNoRows) {
			if node.Budget == nil {
				return errors.New("explicit initial static budget required")
			}
			_, err = tx.Exec(ctx, `INSERT INTO exit_traffic_budgets(exit_id,monthly_bytes,source,is_fallback) VALUES($1,$2,'manual',$3)`, ids[0], node.Budget.MonthlyBytes, node.Budget.Fallback)
			if err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else if node.Budget != nil && (source != "manual" || monthly != node.Budget.MonthlyBytes || fallback != node.Budget.Fallback) {
			return errors.New("existing static budget differs; explicit budget change required")
		}
	}
	return tx.Commit(ctx)
}
