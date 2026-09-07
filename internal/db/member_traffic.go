package db

import (
	"context"
	"fmt"
	"time"
)

type RouteTraffic struct {
	Tag      string `json:"tag"`
	Name     string `json:"name"`
	Uplink   int64  `json:"uplink_bytes"`
	Downlink int64  `json:"downlink_bytes"`
}
type DayTraffic struct {
	Day      string `json:"day"`
	Uplink   int64  `json:"uplink_bytes"`
	Downlink int64  `json:"downlink_bytes"`
}
type RoutePoint struct {
	Bucket   string `json:"bucket"`
	Tag      string `json:"tag"`
	Uplink   int64  `json:"uplink_bytes"`
	Downlink int64  `json:"downlink_bytes"`
}
type MemberTraffic struct {
	DayRoutes []RoutePoint   `json:"day_routes"`
	Hours     []RoutePoint   `json:"hours"`
	Today     string         `json:"today"`
	Limits    []MemberLimit  `json:"limits"`
	Month     string         `json:"month"`
	Uplink    int64          `json:"uplink_bytes"`
	Downlink  int64          `json:"downlink_bytes"`
	Routes    []RouteTraffic `json:"routes"`
	Days      []DayTraffic   `json:"days"`
}

// MemberTraffic returns current-month usage of enrolled accesses only. ID zero is the overview.
func (r *MemberRepo) Traffic(ctx context.Context, id int64, now time.Time) (MemberTraffic, error) {
	now = now.UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	result := MemberTraffic{Today: now.Format("2006-01-02"), DayRoutes: []RoutePoint{}, Hours: []RoutePoint{}, Month: start.Format("2006-01"), Routes: []RouteTraffic{}, Days: []DayTraffic{}}
	filter := `u.enrollment_source IS NOT NULL AND ($1::bigint=0 OR u.telegram_id=$1)`
	e := r.db.Pool.QueryRow(ctx, `SELECT COALESCE(SUM(t.uplink_bytes),0)::bigint,COALESCE(SUM(t.downlink_bytes),0)::bigint FROM monthly_traffic t JOIN users u ON u.uuid=t.user_uuid WHERE `+filter+` AND t.year=$2 AND t.month=$3`, id, now.Year(), int(now.Month())).Scan(&result.Uplink, &result.Downlink)
	if e != nil {
		return result, e
	}
	rows, e := r.db.Pool.Query(ctx, `SELECT t.exit_tag,COALESCE(NULLIF(e.display_name,''),NULLIF(e.country_name,''),NULLIF(e.city,''),e.name,''),SUM(t.uplink_bytes)::bigint,SUM(t.downlink_bytes)::bigint FROM daily_route_traffic t JOIN users u ON u.uuid=t.user_uuid LEFT JOIN exit_nodes e ON 'to-exit-'||e.id::text=t.exit_tag WHERE `+filter+` AND t.day>=$2 AND t.day<$3 GROUP BY t.exit_tag,e.display_name,e.country_name,e.city,e.name ORDER BY SUM(t.uplink_bytes+t.downlink_bytes) DESC`, id, start, end)
	if e != nil {
		return result, e
	}
	var up, down int64
	for rows.Next() {
		var item RouteTraffic
		if e = rows.Scan(&item.Tag, &item.Name, &item.Uplink, &item.Downlink); e != nil {
			rows.Close()
			return result, e
		}
		if item.Name == "" {
			switch item.Tag {
			case "direct":
				item.Name = "Напрямую с bridge · Yandex Cloud"
			case "block":
				item.Name = "Заблокировано"
			default:
				item.Name = "Другой или удалённый выход"
			}
		}
		up += item.Uplink
		down += item.Downlink
		result.Routes = append(result.Routes, item)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return result, e
	}
	if result.Uplink > up || result.Downlink > down {
		result.Routes = append(result.Routes, RouteTraffic{Tag: "unknown", Name: "Выход не определён · прежняя статистика", Uplink: max(0, result.Uplink-up), Downlink: max(0, result.Downlink-down)})
	}
	rows, e = r.db.Pool.Query(ctx, `SELECT (t.collected_at AT TIME ZONE 'UTC')::date::text,SUM(t.uplink_bytes)::bigint,SUM(t.downlink_bytes)::bigint FROM traffic_stats t JOIN users u ON u.uuid=t.user_uuid WHERE `+filter+` AND t.collected_at>=$2 AND t.collected_at<$3 GROUP BY 1 ORDER BY 1`, id, start, end)
	if e != nil {
		return result, e
	}
	defer rows.Close()
	for rows.Next() {
		var day DayTraffic
		if e = rows.Scan(&day.Day, &day.Uplink, &day.Downlink); e != nil {
			return result, fmt.Errorf("traffic day: %w", e)
		}
		result.Days = append(result.Days, day)
	}
	if e = rows.Err(); e != nil {
		return result, e
	}
	rows.Close()
	result.DayRoutes, e = r.routePoints(ctx, id, start, end, false)
	if e != nil {
		return result, e
	}
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	result.Hours, e = r.routePoints(ctx, id, today, today.AddDate(0, 0, 1), true)
	if e != nil {
		return result, e
	}
	result.Limits, e = r.Limits(ctx, id, now)
	return result, e
}

type MemberLimit struct {
	Name      string    `json:"name"`
	ExitID    string    `json:"exit_id"`
	Used      int64     `json:"used_bytes"`
	Limit     int64     `json:"limit_bytes"`
	Remaining int64     `json:"remaining_bytes"`
	ResetsAt  time.Time `json:"resets_at"`
	Monthly   int64     `json:"monthly_bytes"`
	Fallback  bool      `json:"is_fallback"`
	State     string    `json:"state"`
	Reason    string    `json:"reason"`
	Pending   bool      `json:"pending"`
}

func (r *MemberRepo) Limits(ctx context.Context, id int64, now time.Time) ([]MemberLimit, error) {
	out := []MemberLimit{}
	if id == 0 {
		return out, nil
	}
	rows, e := r.db.Pool.Query(ctx, `SELECT b.exit_id::text,COALESCE(NULLIF(n.display_name,''),NULLIF(n.city,''),n.name),b.monthly_bytes,b.is_fallback,q.used_bytes,q.limit_bytes,q.day,q.blocked,q.applied,COALESCE(q.reason,'') FROM exit_traffic_budgets b JOIN exit_nodes n ON n.id=b.exit_id JOIN users u ON u.telegram_id=$1 LEFT JOIN user_exit_quotas q ON q.user_uuid=u.uuid AND q.exit_id=b.exit_id WHERE n.enabled ORDER BY n.priority,n.id`, id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var l MemberLimit
		var used, limit *int64
		var day *time.Time
		var blocked, applied *bool
		if e = rows.Scan(&l.ExitID, &l.Name, &l.Monthly, &l.Fallback, &used, &limit, &day, &blocked, &applied, &l.Reason); e != nil {
			return nil, e
		}
		l.State = "unknown"
		if day != nil && day.Format("2006-01-02") == now.UTC().Format("2006-01-02") && used != nil && limit != nil && blocked != nil {
			l.Used = *used
			l.Limit = *limit
			l.Remaining = max(0, *limit-*used)
			l.ResetsAt = day.AddDate(0, 0, 1)
			l.State = "available"
			if *blocked {
				l.State = "exhausted"
			}
			if l.Reason == "provider_unavailable" {
				l.State = "unknown"
			}
			l.Pending = applied == nil || !*applied
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (r *MemberRepo) Budgets(ctx context.Context) ([]ExitBudget, error) {
	return NewQuotaRepo(r.db).Budgets(ctx)
}

func (r *MemberRepo) routePoints(ctx context.Context, id int64, start, end time.Time, hourly bool) ([]RoutePoint, error) {
	table, stamp, bucket := "daily_route_traffic", "t.day", "t.day::text"
	if hourly {
		table, stamp, bucket = "traffic_stats", "t.collected_at", "to_char(t.collected_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:00')"
	}
	query := `SELECT ` + bucket + `,t.exit_tag,SUM(t.uplink_bytes)::bigint,SUM(t.downlink_bytes)::bigint FROM ` + table + ` t JOIN users u ON u.uuid=t.user_uuid WHERE u.enrollment_source IS NOT NULL AND ($1::bigint=0 OR u.telegram_id=$1) AND ` + stamp + ` >=$2 AND ` + stamp + ` <$3 AND t.exit_tag<>'' GROUP BY 1,2 ORDER BY 1,2`
	rows, e := r.db.Pool.Query(ctx, query, id, start, end)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []RoutePoint{}
	for rows.Next() {
		var p RoutePoint
		if e = rows.Scan(&p.Bucket, &p.Tag, &p.Uplink, &p.Downlink); e != nil {
			return nil, e
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
