package cloud

import (
	"context"
	"encoding/json"
	"math"
	"time"
)

// Account exposes only billing figures, never account identity or API permissions.
type Account struct {
	Balance    json.Number `json:"balance"`
	Pending    json.Number `json:"pending_charges"`
	ObservedAt time.Time   `json:"observed_at"`
}

func (v *Vultr) Account(ctx context.Context) (Account, error) {
	var response struct {
		Account *Account `json:"account"`
	}
	if e := v.request(ctx, "GET", "/account", nil, &response); e != nil {
		return Account{}, e
	}
	if response.Account == nil {
		return Account{}, ErrUnavailable
	}
	a := *response.Account
	if v, e := a.Balance.Float64(); e != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return Account{}, ErrUnavailable
	}
	if v, e := a.Pending.Float64(); e != nil || v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
		return Account{}, ErrUnavailable
	}
	a.ObservedAt = time.Now().UTC()
	return a, nil
}
