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

func (v *Vultr) AccountBandwidth(ctx context.Context) (AccountBandwidth, error) {
	var response struct {
		Bandwidth struct {
			Current *struct {
				Out       *float64 `json:"gb_out"`
				Instance  *float64 `json:"instance_bandwidth_credits"`
				Free      *float64 `json:"free_bandwidth_credits"`
				Purchased *float64 `json:"purchased_bandwidth_credits"`
			} `json:"current_month_to_date"`
		} `json:"bandwidth"`
	}
	if e := v.request(ctx, "GET", "/account/bandwidth", nil, &response); e != nil {
		return AccountBandwidth{}, e
	}
	c := response.Bandwidth.Current
	if c == nil || c.Out == nil || c.Instance == nil || c.Free == nil || c.Purchased == nil || *c.Out < 0 || *c.Instance < 0 ||
		*c.Free < 0 ||
		*c.Purchased < 0 {
		return AccountBandwidth{}, ErrUnavailable
	}
	credits := (*c.Instance + *c.Free + *c.Purchased) * 1e9
	used := *c.Out * 1e9
	amount := credits*0.8 - used
	if math.IsNaN(credits) || math.IsInf(credits, 0) || credits >= float64(math.MaxInt64) || math.IsNaN(used) || math.IsInf(used, 0) ||
		used >= float64(math.MaxInt64) {
		return AccountBandwidth{}, ErrUnavailable
	}
	return AccountBandwidth{Accrued: int64(credits), Used: int64(used), Remaining: max(0, int64(amount))}, nil
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
