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
)

const (
	leakPollInterval          = 30 * time.Second
	leakAlertCooldown         = 6 * time.Hour
	defaultLeakMaxConcurrent  = 2
	defaultLeakMaxUnique24h   = 5
	defaultStatsAPIListenAddr = "127.0.0.1:10085"
)

func (b *Bot) runLeakDetector(ctx context.Context) {
	t := time.NewTicker(leakPollInterval)
	defer t.Stop()

	statsAddr := os.Getenv("ULTRA_XRAY_STATS_API")
	if statsAddr == "" {
		statsAddr = defaultStatsAPIListenAddr
	}
	lastAlertAt := map[string]time.Time{}

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			onlineByUser, err := fetchOnlineIPList(ctx, statsAddr)
			if err != nil {
				b.log.Warn("leak: fetch online IP list failed", "err", err)
				continue
			}
			users, err := b.fetchUsersForLeak(ctx)
			if err != nil {
				b.log.Warn("leak: fetch users failed", "err", err)
				continue
			}
			for _, u := range users {
				ips := onlineByUser[u.UUID]
				for _, ip := range ips {
					if err := b.teleRepo.UpsertUserIPObservation(ctx, u.UUID, ip); err != nil {
						b.log.Warn("leak: upsert ip observation failed", "user_uuid", u.UUID, "ip", ip, "err", err)
					}
				}
				b.evalLeakForUser(ctx, u, ips, lastAlertAt)
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
	UUID                 string `json:"uuid"`
	Name                 string `json:"name"`
	IsActive             bool   `json:"is_active"`
	LeakPolicy           string `json:"leak_policy"`
	LeakMaxConcurrentIPs *int   `json:"leak_max_concurrent_ips"`
	LeakMaxUniqueIPs24h  *int   `json:"leak_max_unique_ips_24h"`
}

func (b *Bot) evalLeakForUser(ctx context.Context, u dbUserLeakCfg, currentIPs []string, last map[string]time.Time) {
	if !u.IsActive {
		return
	}
	policy := strings.TrimSpace(strings.ToLower(u.LeakPolicy))
	if policy == "" {
		policy = "alert"
	}
	if policy == "off" {
		return
	}

	maxConcurrent := defaultLeakMaxConcurrent
	if u.LeakMaxConcurrentIPs != nil && *u.LeakMaxConcurrentIPs > 0 {
		maxConcurrent = *u.LeakMaxConcurrentIPs
	}
	maxUnique24h := defaultLeakMaxUnique24h
	if u.LeakMaxUniqueIPs24h != nil && *u.LeakMaxUniqueIPs24h > 0 {
		maxUnique24h = *u.LeakMaxUniqueIPs24h
	}

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
		return
	}
	if t, ok := last[u.UUID]; ok && time.Since(t) < leakAlertCooldown {
		return
	}

	score := 60
	kind := "concurrent_ips"
	if unique24h > maxUnique24h {
		score = 80
		kind = "unique_ips_window"
	}
	detail := map[string]any{
		"concurrent_ips":           concurrent,
		"concurrent_threshold":     maxConcurrent,
		"unique_ips_24h":           unique24h,
		"unique_ips_24h_threshold": maxUnique24h,
		"current_ips":              currentIPs,
		"policy":                   policy,
	}
	if err := b.teleRepo.InsertLeakSignal(ctx, u.UUID, kind, score, detail); err != nil {
		b.log.Warn("leak: insert signal failed", "user_uuid", u.UUID, "err", err)
	}
	b.enqueueAdminAlert(ctx, "token_leak", map[string]any{
		"text":      "Подозрительная активность токена: " + u.Name,
		"user_uuid": u.UUID,
		"kind":      kind,
		"score":     score,
	})
	last[u.UUID] = time.Now()

	switch policy {
	case "rotate":
		if _, err := b.adminPost(ctx, "/v1/users/"+u.UUID+"/rotate", nil); err != nil {
			b.log.Warn("leak: auto-rotate failed", "user_uuid", u.UUID, "err", err)
		}
	case "disable":
		if err := b.adminDelete(ctx, "/v1/users/"+u.UUID); err != nil {
			b.log.Warn("leak: auto-disable failed", "user_uuid", u.UUID, "err", err)
		}
	}
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
// fetches the IP list for each one via GetStatsOnlineIpList. The user identity
// (`email` field of the VLESS client config) equals the UUID in our setup.
func collectOnlineIPList(ctx context.Context, client statsIPClient) (map[string][]string, error) {
	all, err := client.GetAllOnlineUsers(ctx, &xraycmd.GetAllOnlineUsersRequest{})
	if err != nil {
		return nil, err
	}
	users := all.GetUsers()
	out := make(map[string][]string, len(users))
	for _, email := range users {
		email = strings.TrimSpace(email)
		if email == "" {
			continue
		}
		resp, err := client.GetStatsOnlineIpList(ctx, &xraycmd.GetStatsRequest{Name: email})
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
