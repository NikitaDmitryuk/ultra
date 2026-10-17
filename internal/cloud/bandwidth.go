package cloud

import (
	"context"
	"math"
	"net/url"
	"time"
)

// AccountBandwidth is the accrued account-wide pool, in decimal bytes.
type AccountBandwidth struct {
	Accrued   int64
	Used      int64
	Remaining int64
}

const (
	// Vultr's account egress allowance is decimal: 2 TB plus 1 TB for each
	// instance that still exists in the account. Stopped instances remain in
	// /instances and therefore remain billable; deleted instances disappear.
	VultrBaseBandwidthBytes    int64 = 2_000_000_000_000
	VultrPerInstanceBytes      int64 = 1_000_000_000_000
	VultrSafeBudgetNumerator         = 4
	VultrSafeBudgetDenominator       = 5
)

func vultrBandwidthCapacity(instances int) (int64, error) {
	if instances < 0 || int64(instances) > (math.MaxInt64-VultrBaseBandwidthBytes)/VultrPerInstanceBytes {
		return 0, ErrUnavailable
	}
	return VultrBaseBandwidthBytes + int64(instances)*VultrPerInstanceBytes, nil
}

func vultrSafeBandwidthBudget(capacity int64) int64 {
	return capacity/VultrSafeBudgetDenominator*VultrSafeBudgetNumerator +
		capacity%VultrSafeBudgetDenominator*VultrSafeBudgetNumerator/VultrSafeBudgetDenominator
}

func (v *Vultr) AccountBandwidth(ctx context.Context) (AccountBandwidth, error) {
	var response struct {
		Bandwidth struct {
			Current *struct {
				Out *float64 `json:"gb_out"`
			} `json:"current_month_to_date"`
		} `json:"bandwidth"`
	}
	if e := v.request(ctx, "GET", "/account/bandwidth", nil, &response); e != nil {
		return AccountBandwidth{}, e
	}
	c := response.Bandwidth.Current
	if c == nil || c.Out == nil || *c.Out < 0 {
		return AccountBandwidth{}, ErrUnavailable
	}
	used := *c.Out * 1e9
	if math.IsNaN(used) || math.IsInf(used, 0) || used >= float64(math.MaxInt64) {
		return AccountBandwidth{}, ErrUnavailable
	}
	instances, err := v.Instances(ctx)
	if err != nil {
		return AccountBandwidth{}, err
	}
	capacity, err := vultrBandwidthCapacity(len(instances))
	if err != nil {
		return AccountBandwidth{}, err
	}
	safe := vultrSafeBandwidthBudget(capacity)
	return AccountBandwidth{Accrued: capacity, Used: int64(used), Remaining: max(0, safe-int64(used))}, nil
}

// AccountRemaining retains the read-only API used by account diagnostics.
func (v *Vultr) AccountRemaining(ctx context.Context) (int64, error) {
	b, err := v.AccountBandwidth(ctx)
	return b.Remaining, err
}
func (v *Vultr) InstanceBandwidth(ctx context.Context, id string, now time.Time) (int64, error) {
	var response struct {
		Bandwidth map[string]struct {
			Out int64 `json:"outgoing_bytes"`
		} `json:"bandwidth"`
	}
	if e := v.request(ctx, "GET", "/instances/"+url.PathEscape(id)+"/bandwidth", nil, &response); e != nil {
		return 0, e
	}
	if response.Bandwidth == nil {
		return 0, ErrUnavailable
	}
	var total int64
	for date, entry := range response.Bandwidth {
		if len(date) < 10 {
			return 0, ErrUnavailable
		}
		parsed, err := time.Parse("2006-01-02", date[:10])
		if err != nil || entry.Out < 0 {
			return 0, ErrUnavailable
		}
		if parsed.Format("2006-01") == now.UTC().Format("2006-01") {
			if entry.Out > math.MaxInt64-total {
				return 0, ErrUnavailable
			}
			total += entry.Out
		}
	}
	return total, nil
}
