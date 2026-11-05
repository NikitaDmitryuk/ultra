package db

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/jackc/pgx/v5"
)

// PersonalNotificationPreferences is deliberately an opt-in, self-only contract.
type PersonalNotificationPreferences struct {
	Credentials  bool `json:"credentials"`
	Access       bool `json:"access"`
	Quota        bool `json:"quota"`
	Availability bool `json:"availability"`
}

var ErrPersonalNotificationPending = errors.New("personal notification awaiting runtime acknowledgement")

const PersonalNotificationMaxAttempts = 12
const PersonalNotificationMaxAge = 24 * time.Hour

type PersonalNotificationRepo struct{ db *DB }

func NewPersonalNotificationRepo(d *DB) *PersonalNotificationRepo {
	return &PersonalNotificationRepo{d}
}

func (r *PersonalNotificationRepo) Preferences(ctx context.Context, telegram int64) (p PersonalNotificationPreferences, err error) {
	err = r.db.Pool.QueryRow(ctx, `SELECT p.credentials,p.access,p.quota,p.availability FROM personal_notification_preferences p JOIN users u USING(account_id) WHERE u.telegram_id=$1 AND u.kind='vless' AND NOT EXISTS(SELECT 1 FROM service_access s WHERE s.account_id=u.account_id)`, telegram).
		Scan(&p.Credentials, &p.Access, &p.Quota, &p.Availability)
	return
}
func (r *PersonalNotificationRepo) PutPreferences(ctx context.Context, telegram int64, p PersonalNotificationPreferences) error {
	tag, e := r.db.Pool.Exec(ctx, `UPDATE personal_notification_preferences p SET
 credentials=$2,access=$3,quota=$4,availability=$5,
 credentials_since=CASE WHEN credentials<>$2 THEN clock_timestamp() ELSE credentials_since END,
 access_since=CASE WHEN access<>$3 THEN clock_timestamp() ELSE access_since END,
 quota_since=CASE WHEN quota<>$4 THEN clock_timestamp() ELSE quota_since END,
 availability_since=CASE WHEN availability<>$5 THEN clock_timestamp() ELSE availability_since END
 FROM users u WHERE u.account_id=p.account_id AND u.telegram_id=$1 AND u.kind='vless' AND NOT EXISTS(SELECT 1 FROM service_access s WHERE s.account_id=u.account_id)`, telegram, p.Credentials, p.Access, p.Quota, p.Availability)
	if e == nil && tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	return e
}

// enqueuePersonal is called in the same transaction as the event/state change.
func enqueuePersonal(ctx context.Context, tx pgx.Tx, account, category, kind string, revision, incident int64) error {
	_, e := tx.Exec(ctx, `INSERT INTO personal_notification_events(account_id,category,kind,revision,incident)
 SELECT account_id,$2,$3,$4,$5 FROM personal_notification_preferences p
 WHERE account_id=$1 AND CASE $2 WHEN 'credentials' THEN credentials WHEN 'access' THEN access WHEN 'quota' THEN quota WHEN 'availability' THEN availability ELSE false END
 ON CONFLICT DO NOTHING`, account, category, kind, revision, incident)
	return e
}

// personalCredentialChange contains no token or UUID payload. Own successful
// cabinet operations pass suppress=true while still invalidating older events.
func personalCredentialChange(ctx context.Context, tx pgx.Tx, id, kind string, suppress bool) error {
	var account string
	var revision int64
	e := tx.QueryRow(ctx, `UPDATE personal_notification_preferences p SET credential_revision=credential_revision+1 FROM users u WHERE u.account_id=p.account_id AND u.uuid=$1 RETURNING p.account_id::text,p.credential_revision`, id).
		Scan(&account, &revision)
	if e != nil {
		return e
	}
	if suppress {
		return nil
	}
	return enqueuePersonal(ctx, tx, account, "credentials", kind, revision, 0)
}

type personalActorKey struct{}

func WithPersonalNotificationSuppressed(ctx context.Context) context.Context {
	return context.WithValue(ctx, personalActorKey{}, true)
}
func personalSuppressed(ctx context.Context) bool {
	v, _ := ctx.Value(personalActorKey{}).(bool)
	return v
}

// AccessSnapshot binds the acknowledgement to the exact desired values loaded
// for this apply. A later change cannot be acknowledged by an earlier apply.
type PersonalAccessSnapshot struct {
	Account, UUID string
	Active        bool
	Revision      int64
}

func (r *PersonalNotificationRepo) AccessSnapshot(ctx context.Context) ([]PersonalAccessSnapshot, error) {
	rows, e := r.db.Pool.Query(
		ctx,
		`SELECT u.account_id::text,u.uuid::text,u.is_active,p.access_revision FROM users u JOIN personal_notification_preferences p USING(account_id) WHERE u.kind='vless'`,
	)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []PersonalAccessSnapshot{}
	for rows.Next() {
		var v PersonalAccessSnapshot
		if e = rows.Scan(&v.Account, &v.UUID, &v.Active, &v.Revision); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ConfirmAccess must only follow successful application of precisely users.
func (r *PersonalNotificationRepo) ConfirmAccess(ctx context.Context, snapshot []PersonalAccessSnapshot, users []auth.User) error {
	desired := map[string]bool{}
	for _, u := range users {
		desired[u.UUID] = u.IsActive
	}
	for _, v := range snapshot {
		active, ok := desired[v.UUID]
		if !ok || active != v.Active {
			continue
		}
		tx, e := r.db.Pool.Begin(ctx)
		if e != nil {
			return e
		}
		var current bool
		var revision int64
		var raw []byte
		e = tx.QueryRow(ctx, `SELECT u.is_active,p.access_revision,p.observed FROM personal_notification_preferences p JOIN users u USING(account_id) WHERE p.account_id=$1 AND u.uuid=$2 FOR UPDATE OF p`, v.Account, v.UUID).
			Scan(&current, &revision, &raw)
		if e != nil {
			_ = tx.Rollback(ctx)
			if errors.Is(e, pgx.ErrNoRows) {
				continue
			}
			return e
		}
		if current != v.Active || revision != v.Revision {
			_ = tx.Rollback(ctx)
			continue
		}
		var st personalObservation
		if e = json.Unmarshal(raw, &st); e != nil {
			_ = tx.Rollback(ctx)
			return e
		}
		if st.AccessSet && st.Access != current {
			kind := "disabled"
			if current {
				kind = "enabled"
			}
			e = enqueuePersonal(ctx, tx, v.Account, "access", kind, revision, 0)
		}
		st.AccessSet = true
		st.Access = current
		st.AppliedUUID = v.UUID
		if e == nil {
			raw, e = json.Marshal(st)
		}
		if e == nil {
			_, e = tx.Exec(ctx, `UPDATE personal_notification_preferences SET observed=$2 WHERE account_id=$1`, v.Account, raw)
		}
		if e == nil {
			e = tx.Commit(ctx)
		} else {
			_ = tx.Rollback(ctx)
		}
		if e != nil {
			return e
		}
	}
	return nil
}

// PersonalRouteObservation comes only from the existing runtime routing and
// health snapshot, never from failure to contact an API.
type PersonalRouteObservation struct {
	Account      string `json:"account"`
	Known        bool   `json:"known"`
	QuotaBlocked bool   `json:"quota_blocked"`
	Available    bool   `json:"available"`
}
type personalObservation struct {
	Known         bool
	AppliedUUID   string
	AccessSet     bool
	Access        bool
	QuotaSet      bool
	Quota         bool
	QuotaRevision int64
	DownSince     time.Time
	UpSince       time.Time
	LastSample    time.Time
	Incident      int64
	Down          bool
	RecoveredAt   time.Time
}

func (s *personalObservation) observe(v PersonalRouteObservation, now time.Time) (quotaKind, availabilityKind string) {
	// Gaps and unknown observations break continuity, including across downtime.
	if !v.Known || (!s.LastSample.IsZero() && (now.Sub(s.LastSample) > 90*time.Second || now.Before(s.LastSample))) {
		s.DownSince = time.Time{}
		s.UpSince = time.Time{}
	}
	s.LastSample = now
	s.Known = v.Known
	if !v.Known {
		return
	}
	if s.QuotaSet && s.Quota != v.QuotaBlocked {
		s.QuotaRevision++
		quotaKind = "limited"
		if !v.QuotaBlocked {
			quotaKind = "restored"
		}
	}
	s.QuotaSet = true
	s.Quota = v.QuotaBlocked
	// Quota is its own cause; it cannot start or recover an availability incident.
	if v.QuotaBlocked {
		s.DownSince = time.Time{}
		s.UpSince = time.Time{}
		return
	}
	if v.Available {
		s.DownSince = time.Time{}
		if s.UpSince.IsZero() {
			s.UpSince = now
		}
		if s.Down && now.Sub(s.UpSince) >= 2*time.Minute {
			s.Down = false
			s.RecoveredAt = now
			availabilityKind = "recovered"
		}
	} else {
		s.UpSince = time.Time{}
		if s.DownSince.IsZero() {
			s.DownSince = now
		}
		if !s.Down && now.Sub(s.DownSince) >= 5*time.Minute && (s.RecoveredAt.IsZero() || now.Sub(s.RecoveredAt) >= 30*time.Minute) {
			s.Down = true
			s.Incident++
			availabilityKind = "down"
		}
	}
	return
}
func (r *PersonalNotificationRepo) Observe(ctx context.Context, observations []PersonalRouteObservation, now time.Time) error {
	for _, v := range observations {
		tx, e := r.db.Pool.Begin(ctx)
		if e != nil {
			return e
		}
		var raw []byte
		e = tx.QueryRow(ctx, `SELECT observed FROM personal_notification_preferences p WHERE account_id=$1 AND EXISTS(SELECT 1 FROM users u WHERE u.account_id=p.account_id AND u.is_active AND NOT u.member_pending) FOR UPDATE`, v.Account).
			Scan(&raw)
		if e != nil {
			_ = tx.Rollback(ctx)
			if errors.Is(e, pgx.ErrNoRows) {
				continue
			}
			return e
		}
		var st personalObservation
		e = json.Unmarshal(raw, &st)
		if e == nil {
			q, a := st.observe(v, now)
			if q != "" {
				e = enqueuePersonal(ctx, tx, v.Account, "quota", q, st.QuotaRevision, 0)
			}
			if e == nil && a != "" {
				e = enqueuePersonal(ctx, tx, v.Account, "availability", a, st.Incident, st.Incident)
			}
		}
		if e == nil {
			raw, e = json.Marshal(st)
		}
		if e == nil {
			_, e = tx.Exec(ctx, `UPDATE personal_notification_preferences SET observed=$2 WHERE account_id=$1`, v.Account, raw)
		}
		if e == nil {
			e = tx.Commit(ctx)
		} else {
			_ = tx.Rollback(ctx)
		}
		if e != nil {
			return e
		}
	}
	return nil
}

type PersonalNotification struct {
	ID         int64  `json:"id"`
	Account    string `json:"account"`
	Category   string `json:"category"`
	Kind       string `json:"kind"`
	Revision   int64  `json:"revision"`
	Incident   int64  `json:"incident"`
	Attempts   int    `json:"attempts"`
	TelegramID int64  `json:"telegram_id"`
	UUID       string `json:"-"`
}

func (r *PersonalNotificationRepo) Claim(ctx context.Context) (n PersonalNotification, err error) {
	_, err = r.db.Pool.Exec(
		ctx,
		`UPDATE personal_notification_events SET terminal=true WHERE sent_at IS NULL AND NOT terminal AND (attempts>=$1 OR created_at<clock_timestamp()-$2*interval '1 second') AND (lease_until IS NULL OR lease_until<clock_timestamp())`,
		PersonalNotificationMaxAttempts,
		PersonalNotificationMaxAge.Seconds(),
	)
	if err != nil {
		return
	}
	err = r.db.Pool.QueryRow(ctx, `UPDATE personal_notification_events n SET attempts=attempts+1,lease_until=clock_timestamp()+interval '1 minute' WHERE id=(SELECT id FROM personal_notification_events WHERE sent_at IS NULL AND NOT terminal AND next_attempt_at<=now() AND (lease_until IS NULL OR lease_until<clock_timestamp()) ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING id,account_id::text,category,kind,revision,incident,attempts`).
		Scan(&n.ID, &n.Account, &n.Category, &n.Kind, &n.Revision, &n.Incident, &n.Attempts)
	return
}

// Eligible rechecks preferences, incarnation, supersession and onset delivery.
func (r *PersonalNotificationRepo) Eligible(ctx context.Context, n *PersonalNotification) (bool, error) {
	var raw []byte
	var active, pending, enabled, claimed bool
	var credentialRevision, accessRevision int64
	var since, created time.Time
	e := r.db.Pool.QueryRow(ctx, `SELECT n.account_id::text,n.category,n.kind,n.revision,n.incident,u.telegram_id,u.uuid::text,u.is_active,u.member_pending,
 CASE n.category WHEN 'credentials' THEN p.credentials WHEN 'access' THEN p.access WHEN 'quota' THEN p.quota WHEN 'availability' THEN p.availability END,
 CASE n.category WHEN 'credentials' THEN p.credentials_since WHEN 'access' THEN p.access_since WHEN 'quota' THEN p.quota_since WHEN 'availability' THEN p.availability_since END,
 p.credential_revision,p.access_revision,p.observed,n.created_at,n.attempts=$2 AND n.lease_until>clock_timestamp() AND n.sent_at IS NULL AND NOT n.terminal AND n.created_at>=clock_timestamp()-interval '24 hours'
 FROM personal_notification_events n JOIN personal_notification_preferences p USING(account_id) JOIN users u USING(account_id)
 WHERE n.id=$1 AND u.telegram_id>0 AND u.kind='vless' AND NOT EXISTS(SELECT 1 FROM service_access s WHERE s.account_id=u.account_id)`, n.ID, n.Attempts).
		Scan(&n.Account, &n.Category, &n.Kind, &n.Revision, &n.Incident, &n.TelegramID, &n.UUID, &active, &pending, &enabled, &since, &credentialRevision, &accessRevision, &raw, &created, &claimed)
	if errors.Is(e, pgx.ErrNoRows) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	if !enabled || !claimed || created.Before(since) {
		return false, nil
	}
	var st personalObservation
	if e = json.Unmarshal(raw, &st); e != nil {
		return false, e
	}
	switch n.Category {
	case "credentials":
		if !active || credentialRevision != n.Revision {
			return false, nil
		}
		if pending || (n.Kind == "uuid" && st.AppliedUUID != n.UUID) {
			return false, ErrPersonalNotificationPending
		}
		return true, nil
	case "access":
		return accessRevision == n.Revision && st.AccessSet && st.Access == (n.Kind == "enabled"), nil
	case "quota":
		if !st.Known || time.Since(st.LastSample) > 90*time.Second {
			return false, ErrPersonalNotificationPending
		}
		return active && !pending && st.QuotaRevision == n.Revision && st.Quota == (n.Kind == "limited"), nil
	case "availability":
		if !st.Known || time.Since(st.LastSample) > 90*time.Second {
			return false, ErrPersonalNotificationPending
		}
		if !active || pending || st.Incident != n.Incident || st.Down != (n.Kind == "down") {
			return false, nil
		}
		if n.Kind == "recovered" {
			if st.Quota || st.UpSince.IsZero() {
				return false, nil
			}
			var sent bool
			e = r.db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM personal_notification_events WHERE account_id=$1 AND category='availability' AND kind='down' AND incident=$2 AND sent_at IS NOT NULL AND delivered_to=$3 AND created_at>=$4)`, n.Account, n.Incident, n.TelegramID, since).
				Scan(&sent)
			return sent, e
		}
		return !st.Quota && st.UpSince.IsZero() && !st.DownSince.IsZero(), nil
	}
	return false, nil
}
func (r *PersonalNotificationRepo) Complete(ctx context.Context, n PersonalNotification, sent, terminal bool, delay time.Duration) error {
	_, e := r.db.Pool.Exec(
		ctx,
		`UPDATE personal_notification_events SET sent_at=CASE WHEN $3 THEN clock_timestamp() ELSE sent_at END,delivered_to=CASE WHEN $3 THEN $6 ELSE delivered_to END,terminal=$4,lease_until=NULL,next_attempt_at=clock_timestamp()+$5*interval '1 second' WHERE id=$1 AND attempts=$2 AND lease_until>clock_timestamp() AND sent_at IS NULL AND NOT terminal`,
		n.ID,
		n.Attempts,
		sent,
		terminal,
		delay.Seconds(),
		n.TelegramID,
	)
	return e
}
