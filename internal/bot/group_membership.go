package bot

import (
	"context"
	"github.com/NikitaDmitryuk/ultra/internal/db"
	"sort"
	"sync"
	"time"
)

type membershipStatus struct {
	State     string     `json:"state"`
	CheckedAt *time.Time `json:"checked_at,omitempty"`
}
type membershipCache struct {
	sync.Mutex
	group     int64
	available bool
	items     map[int64]membershipStatus
}
type memberView struct {
	db.Member
	Group membershipStatus `json:"group_membership"`
}

func (b *Bot) memberView(m db.Member) memberView {
	b.memberships.Lock()
	defer b.memberships.Unlock()
	status := membershipStatus{State: "checking"}
	if !b.memberships.available {
		status.State = "unknown"
	} else if b.memberships.group == 0 {
		status.State = "not_configured"
	} else if value, ok := b.memberships.items[m.TelegramID]; ok {
		status = value
		if value.CheckedAt == nil || time.Since(*value.CheckedAt) > 6*time.Minute {
			status.State = "unknown"
		}
	}
	return memberView{Member: m, Group: status}
}
func (b *Bot) runGroupMembership(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c, cancel := context.WithTimeout(ctx, 9*time.Second)
			b.refreshGroupMembership(c)
			cancel()
		}
	}
}
func (b *Bot) refreshGroupMembership(ctx context.Context) {
	var group db.VPNGroup
	if _, e := b.relayJSON(ctx, "GET", "/v1/enrollment/group", nil, &group); e != nil {
		b.memberships.Lock()
		b.memberships.available = false
		b.memberships.Unlock()
		return
	}
	b.memberships.Lock()
	if b.memberships.group != group.ChatID || b.memberships.items == nil {
		b.memberships.items = map[int64]membershipStatus{}
	}
	b.memberships.group = group.ChatID
	b.memberships.available = true
	b.memberships.Unlock()
	if group.ChatID == 0 {
		return
	}
	var members []db.Member
	if _, e := b.relayJSON(ctx, "GET", "/v1/members", nil, &members); e != nil {
		return
	}
	type pending struct {
		id int64
		at time.Time
	}
	due := []pending{}
	b.memberships.Lock()
	for _, m := range members {
		v := b.memberships.items[m.TelegramID]
		var at time.Time
		if v.CheckedAt != nil {
			at = *v.CheckedAt
		}
		ttl := 5 * time.Minute
		if v.State == "unknown" {
			ttl = time.Minute
		}
		if time.Since(at) >= ttl {
			due = append(due, pending{m.TelegramID, at})
		}
	}
	b.memberships.Unlock()
	sort.Slice(due, func(i, j int) bool { return due[i].at.Before(due[j].at) })
	if len(due) > 4 {
		due = due[:4]
	}
	for _, item := range due {
		if ctx.Err() != nil {
			return
		}
		var result struct {
			Status   string `json:"status"`
			IsMember bool   `json:"is_member"`
		}
		e := b.telegramJSON(ctx, "getChatMember", map[string]any{"chat_id": group.ChatID, "user_id": item.id}, &result)
		now := time.Now().UTC()
		value := membershipStatus{State: "unknown", CheckedAt: &now}
		if e == nil {
			value.State = "outside"
			if allowedMember(result.Status, result.IsMember) {
				value.State = "inside"
			}
		}
		b.memberships.Lock()
		if b.memberships.group == group.ChatID {
			b.memberships.items[item.id] = value
		}
		b.memberships.Unlock()
	}
}
