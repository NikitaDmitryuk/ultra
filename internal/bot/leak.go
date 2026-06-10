package bot

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	xraycmd "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
)

const (
	leakPollInterval          = 30 * time.Second
	leakConcurrentCooldown    = 6 * time.Hour
	leakUniqueWindowCooldown  = 24 * time.Hour
	leakConfirmSamples        = 2
	leakHeartbeatInterval     = 5 * time.Minute
	defaultLeakMaxConcurrent  = 5
	defaultLeakMaxUnique24h   = 20
	strongLeakMaxUnique24h    = 30
	defaultStatsAPIListenAddr = "127.0.0.1:10085"

	// onlineKey* match the format Xray's dispatcher uses to register online maps:
	//   "user>>>" + email + ">>>online"
	// (see github.com/xtls/xray-core app/dispatcher/default.go).
	onlineKeyPrefix = "user>>>"
	onlineKeySuffix = ">>>online"
)

type leakBreachState struct {
	Kind     string
	Strength string
	Streak   int
}

func (b *Bot) runLeakDetector(ctx context.Context) {
	t := time.NewTicker(leakPollInterval)
	defer t.Stop()
	heartbeat := time.NewTicker(leakHeartbeatInterval)
	defer heartbeat.Stop()

	statsAddr := os.Getenv("ULTRA_XRAY_STATS_API")
	if statsAddr == "" {
		statsAddr = defaultStatsAPIListenAddr
	}
	breachState := map[string]leakBreachState{}
	var lastOnline int

	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			b.log.Info("leak: poll", "online_users", lastOnline, "stats_api", statsAddr)
		case <-t.C:
			onlineByUser, err := fetchOnlineIPList(ctx, statsAddr)
			if err != nil {
				b.log.Warn("leak: fetch online IP list failed", "err", err)
				continue
			}
			lastOnline = len(onlineByUser)
			users, err := b.fetchUsersForLeak(ctx)
			if err != nil {
				b.log.Warn("leak: fetch users failed", "err", err)
				continue
			}
			for _, u := range users {
				if u.UUID == auth.LegacySocksUserUUID {
					continue
				}
				ips := onlineByUser[u.UUID]
				for _, ip := range ips {
					if err := b.teleRepo.UpsertUserIPObservation(ctx, u.UUID, ip); err != nil {
						b.log.Warn("leak: upsert ip observation failed", "user_uuid", u.UUID, "ip", ip, "err", err)
					}
				}
				b.evalLeakForUser(ctx, u, ips, breachState)
			}
		}
	}
}

func (b *Bot) fetchUsersForLeak(ctx context.Context) ([]dbUserLeakCfg, error) {
	body, err := b.adminGet(ctx, "/v1/users")
	if err != nil {
		return nil, err
	}
	var rows []dbUserLeakCfg
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

type dbUserLeakCfg struct {
	UUID     string `json:"uuid"`
	Name     string `json:"name"`
	IsActive bool   `json:"is_active"`
}

func (b *Bot) evalLeakForUser(ctx context.Context, u dbUserLeakCfg, currentIPs []string, breachState map[string]leakBreachState) {
	if !u.IsActive {
		return
	}

	// Global thresholds only: same for every user; we only record signals + admin alerts (no auto-rotate / disable).
	maxConcurrent := defaultLeakMaxConcurrent
	maxUnique24h := defaultLeakMaxUnique24h

	concurrent, err := b.teleRepo.CountConcurrentIPs(ctx, u.UUID, time.Minute)
	if err != nil {
		b.log.Warn("leak: count concurrent IPs failed", "user_uuid", u.UUID, "err", err)
		return
	}
	unique24h, err := b.teleRepo.CountUniqueIPs(ctx, u.UUID, 24*time.Hour)
	if err != nil {
		b.log.Warn("leak: count unique 24h IPs failed", "user_uuid", u.UUID, "err", err)
		return
	}
	if concurrent <= maxConcurrent && unique24h <= maxUnique24h {
		delete(breachState, u.UUID)
		return
	}

	decision, ok := classifyLeakBreach(concurrent, unique24h, maxConcurrent, maxUnique24h)
	if !ok {
		delete(breachState, u.UUID)
		return
	}
	dedupeKey := "token_leak." + decision.Strength + ":" + u.UUID + ":" + decision.Kind

	st := updateLeakBreachState(breachState, u.UUID, decision)
	if st.Streak < leakConfirmSamples {
		return
	}
	cooldownActive := false
	if b.alertsTele != nil && decision.Cooldown > 0 {
		state, _, err := b.alertsTele.GetAlertState(ctx, dedupeKey)
		if err != nil {
			b.log.Warn("leak: state read failed", "user_uuid", u.UUID, "kind", decision.Kind, "err", err)
		} else if state.LastSentAt != nil && time.Since(*state.LastSentAt) < decision.Cooldown {
			cooldownActive = true
		}
	}

	detail := map[string]any{
		"concurrent_ips":           concurrent,
		"concurrent_threshold":     maxConcurrent,
		"unique_ips_24h":           unique24h,
		"unique_ips_24h_threshold": maxUnique24h,
		"current_ips":              currentIPs,
		"policy":                   "alert",
	}
	if st.Streak == leakConfirmSamples || !cooldownActive {
		if err := b.teleRepo.InsertLeakSignal(ctx, u.UUID, decision.Kind, decision.Score, detail); err != nil {
			b.log.Warn("leak: insert signal failed", "user_uuid", u.UUID, "err", err)
		}
	}
	if cooldownActive {
		return
	}
	b.emitAlert(ctx, alertEvent{
		DedupeKey: dedupeKey,
		Type:      "token_leak",
		Severity:  decision.Severity,
		Channel:   decision.Channel,
		Status:    "fired",
		Payload: map[string]any{
			"text":                            "Подозрительная активность токена: " + u.Name,
			"user_uuid":                       u.UUID,
			"kind":                            decision.Kind,
			"score":                           decision.Score,
			"concurrent_ips":                  concurrent,
			"concurrent_threshold":            maxConcurrent,
			"unique_ips_24h":                  unique24h,
			"unique_ips_24h_threshold":        maxUnique24h,
			"strong_unique_ips_24h_threshold": strongLeakMaxUnique24h,
		},
		Cooldown: decision.Cooldown,
	})
}

func updateLeakBreachState(states map[string]leakBreachState, userUUID string, decision leakDecision) leakBreachState {
	st := states[userUUID]
	if st.Kind == decision.Kind && st.Strength == decision.Strength {
		st.Streak++
	} else {
		st = leakBreachState{Kind: decision.Kind, Strength: decision.Strength, Streak: 1}
	}
	states[userUUID] = st
	return st
}

type leakDecision struct {
	Kind     string
	Strength string
	Score    int
	Severity string
	Channel  string
	Cooldown time.Duration
}

func classifyLeakBreach(concurrent, unique24h, maxConcurrent, maxUnique24h int) (leakDecision, bool) {
	if unique24h > strongLeakMaxUnique24h {
		return leakDecision{
			Kind:     "unique_ips_window",
			Strength: "strong",
			Score:    80,
			Severity: alertSeverityCritical,
			Channel:  alertChannelTelegram,
			Cooldown: leakUniqueWindowCooldown,
		}, true
	}
	if concurrent > maxConcurrent {
		return leakDecision{
			Kind:     "concurrent_ips",
			Strength: "strong",
			Score:    60,
			Severity: alertSeverityCritical,
			Channel:  alertChannelTelegram,
			Cooldown: leakConcurrentCooldown,
		}, true
	}
	if unique24h > maxUnique24h {
		return leakDecision{
			Kind:     "unique_ips_window",
			Strength: "weak",
			Score:    60,
			Severity: alertSeverityWarning,
			Channel:  alertChannelMiniApp,
			Cooldown: leakUniqueWindowCooldown,
		}, true
	}
	return leakDecision{}, false
}

// statsIPClient is the subset of xray-core StatsServiceClient used by the leak
// detector. It is split off to make collectOnlineIPList testable via a stubbed
// implementation (gRPC bufconn or plain mock).
type statsIPClient interface {
	GetAllOnlineUsers(
		ctx context.Context,
		in *xraycmd.GetAllOnlineUsersRequest,
		opts ...grpc.CallOption,
	) (*xraycmd.GetAllOnlineUsersResponse, error)
	GetStatsOnlineIpList(
		ctx context.Context,
		in *xraycmd.GetStatsRequest,
		opts ...grpc.CallOption,
	) (*xraycmd.GetStatsOnlineIpListResponse, error)
}

// fetchOnlineIPList dials Xray's StatsService and returns currently online users
// mapped to their active client IPs.
func fetchOnlineIPList(ctx context.Context, apiAddr string) (map[string][]string, error) {
	conn, err := grpc.NewClient(apiAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer conn.Close() //nolint:errcheck
	return collectOnlineIPList(ctx, xraycmd.NewStatsServiceClient(conn))
}

// collectOnlineIPList enumerates all online users via GetAllOnlineUsers and then
// fetches the IP list for each one via GetStatsOnlineIpList. Xray dispatcher stores
// online maps under "user>>>{email}>>>online" — GetAllOnlineUsers returns those
// fully-prefixed names verbatim, and GetStatsOnlineIpList expects the same name.
// We strip the prefix/suffix to obtain the bare email/UUID for our internal map.
func collectOnlineIPList(ctx context.Context, client statsIPClient) (map[string][]string, error) {
	all, err := client.GetAllOnlineUsers(ctx, &xraycmd.GetAllOnlineUsersRequest{})
	if err != nil {
		return nil, err
	}
	users := all.GetUsers()
	out := make(map[string][]string, len(users))
	for _, fullName := range users {
		fullName = strings.TrimSpace(fullName)
		if fullName == "" {
			continue
		}
		email := strings.TrimSuffix(strings.TrimPrefix(fullName, onlineKeyPrefix), onlineKeySuffix)
		if email == "" || email == fullName {
			// Either no prefix/suffix matched (unknown format) or the inner email is empty.
			continue
		}
		resp, err := client.GetStatsOnlineIpList(ctx, &xraycmd.GetStatsRequest{Name: fullName})
		if err != nil {
			continue
		}
		ipsMap := resp.GetIps()
		ips := make([]string, 0, len(ipsMap))
		for ip := range ipsMap {
			ips = append(ips, ip)
		}
		out[email] = ips
	}
	return out, nil
}
