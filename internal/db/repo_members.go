package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
	"github.com/jackc/pgx/v5"
	"github.com/xtls/xray-core/common/uuid"
	"gorm.io/gorm"
)

var ErrEnrollmentDenied = errors.New("enrollment unavailable")

type Member struct {
	LastTrafficAt   *time.Time `json:"last_traffic_at"`
	UUID            string     `json:"uuid"`
	TelegramID      int64      `json:"telegram_id"`
	Name            string     `json:"name"`
	Active          bool       `json:"active"`
	Source          string     `json:"source"`
	EnrolledAt      time.Time  `json:"enrolled_at"`
	Pending         bool       `json:"pending"`
	PreferredExitID *string    `json:"preferred_exit_id"`
}
type VPNGroup struct {
	ChatID  int64  `json:"chat_id"`
	Title   string `json:"title"`
	Code    string `json:"code"`
	Enabled bool   `json:"enabled"`
}
type VPNInvite struct {
	RecipientName string     `json:"recipient_name"`
	ID            int64      `json:"id"`
	Recipient     int64      `json:"recipient"`
	CreatedBy     int64      `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	UsedAt        *time.Time `json:"used_at"`
	CancelledAt   *time.Time `json:"cancelled_at"`
}
type MemberRepo struct {
	db    *DB
	state *runtimestate.Store
}

func NewMemberRepo(d *DB) *MemberRepo { return &MemberRepo{db: d} }
func NewRuntimeMemberRepo(d *DB, s *runtimestate.Store) *MemberRepo {
	return &MemberRepo{db: d, state: s}
}
func NewOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func (r *MemberRepo) memberQuery(ctx context.Context) *gorm.DB {
	return r.db.orm.WithContext(ctx).Table("users").Select("uuid, telegram_id, name, is_active AS active, enrollment_source AS source, enrolled_at, member_pending AS pending, preferred_exit_id, (?) AS last_traffic_at", r.db.orm.Table("monthly_traffic AS t").Select("MAX(t.updated_at)").Where("t.user_uuid = users.uuid AND t.uplink_bytes + t.downlink_bytes > 0")).Where("enrollment_source IS NOT NULL")
}
func (r *MemberRepo) Get(ctx context.Context, id int64) (Member, error) {
	var m Member
	e := cloudLookupError(r.memberQuery(ctx).Where("telegram_id = ?", id).Take(&m).Error)
	return m, e
}
func (r *MemberRepo) List(ctx context.Context) ([]Member, error) {
	out := []Member{}
	e := r.memberQuery(ctx).Order("enrolled_at").Find(&out).Error
	return out, e
}
func (r *MemberRepo) Group(ctx context.Context) (VPNGroup, error) {
	var g VPNGroup
	e := cloudLookupError(r.db.orm.WithContext(ctx).Table("vpn_group").Select("chat_id", "title", "code", "enabled").Where("singleton").Take(&g).Error)
	if errors.Is(e, pgx.ErrNoRows) {
		e = nil
	}
	return g, e
}
func (r *MemberRepo) PutGroup(ctx context.Context, g VPNGroup, actor int64) (VPNGroup, error) {
	if g.ChatID >= 0 || actor <= 0 {
		return g, ErrEnrollmentDenied
	}
	var e error
	g.Code, e = NewOpaqueToken()
	if e != nil {
		return g, e
	}
	tx, e := r.db.Pool.Begin(ctx)
	if e != nil {
		return g, e
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	_, e = tx.Exec(ctx, `INSERT INTO vpn_group(singleton,chat_id,title,code,enabled,updated_by) VALUES(true,$1,$2,$3,$4,$5) ON CONFLICT(singleton) DO UPDATE SET chat_id=$1,title=$2,code=$3,enabled=$4,updated_by=$5`, g.ChatID, g.Title, g.Code, g.Enabled, actor)
	if e != nil {
		return g, e
	}
	_, e = tx.Exec(ctx, `INSERT INTO vpn_member_audit(actor,action) VALUES($1,'group_configured')`, actor)
	if e != nil {
		return g, e
	}
	return g, tx.Commit(ctx)
}
func (r *MemberRepo) Invite(ctx context.Context, target, actor int64, recipientName ...string) (string, error) {
	name := ""
	if len(recipientName) > 0 {
		runes := []rune(strings.TrimSpace(recipientName[0]))
		name = string(runes[:min(256, len(runes))])
	}
	if target <= 0 || actor <= 0 {
		return "", ErrEnrollmentDenied
	}
	token, e := NewOpaqueToken()
	if e != nil {
		return "", e
	}
	h := sha256.Sum256([]byte(token))
	tx, e := r.db.Pool.Begin(ctx)
	if e != nil {
		return "", e
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	_, e = tx.Exec(ctx, `INSERT INTO vpn_invites(token_hash,recipient,created_by,expires_at,recipient_name) VALUES($1,$2,$3,NOW()+INTERVAL '7 days',$4)`, h[:], target, actor, name)
	if e != nil {
		return "", e
	}
	_, e = tx.Exec(ctx, `INSERT INTO vpn_member_audit(actor,member_id,action) VALUES($1,$2,'invite_created')`, actor, target)
	if e != nil {
		return "", e
	}
	return token, tx.Commit(ctx)
}
func (r *MemberRepo) Invites(ctx context.Context) ([]VPNInvite, error) {
	out := []VPNInvite{}
	e := r.db.orm.WithContext(ctx).Table("vpn_invites AS i").Select("i.id, i.recipient, i.created_by, i.created_at, i.expires_at, i.used_at, i.cancelled_at, COALESCE(NULLIF(u.name, ''), i.recipient_name) AS recipient_name").Joins("LEFT JOIN users u ON u.telegram_id = i.recipient").Order("i.id DESC").Limit(200).Find(&out).Error
	return out, e
}
func (r *MemberRepo) CancelInvite(ctx context.Context, id, actor int64) error {
	tx, e := r.db.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	_, e = tx.Exec(ctx, `UPDATE vpn_invites SET cancelled_at=NOW() WHERE id=$1 AND used_at IS NULL`, id)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO vpn_member_audit(actor,action) VALUES($1,'invite_cancelled')`, actor)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}

// Enroll is called only by the authenticated relay API. Group proof is obtained by
// the trusted bot; the current code/chat pair is checked again under a row lock.
func (r *MemberRepo) Enroll(ctx context.Context, id int64, name, source, token string, chatID int64) (Member, error) {
	if id <= 0 || (source != "group" && source != "invite") {
		return Member{}, ErrEnrollmentDenied
	}
	tx, e := r.db.Pool.Begin(ctx)
	if e != nil {
		return Member{}, e
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, id); e != nil {
		return Member{}, e
	}
	var existing string
	e = tx.QueryRow(ctx, `SELECT uuid::text FROM users WHERE telegram_id=$1`, id).Scan(&existing)
	if e == nil {
		if e = tx.Commit(ctx); e != nil {
			return Member{}, e
		}
		return r.Get(ctx, id)
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return Member{}, e
	}
	if source == "group" {
		var allowed bool
		e = tx.QueryRow(ctx, `SELECT enabled AND code=$1 AND chat_id=$2 FROM vpn_group WHERE singleton FOR UPDATE`, token, chatID).Scan(&allowed)
		if e != nil || !allowed {
			return Member{}, ErrEnrollmentDenied
		}
	} else {
		h := sha256.Sum256([]byte(token))
		var inviteID int64
		e = tx.QueryRow(ctx, `SELECT id FROM vpn_invites WHERE token_hash=$1 AND recipient=$2 AND expires_at>NOW() AND used_at IS NULL AND cancelled_at IS NULL FOR UPDATE`, h[:], id).Scan(&inviteID)
		if e != nil {
			return Member{}, ErrEnrollmentDenied
		}
		if _, e = tx.Exec(ctx, `UPDATE vpn_invites SET used_at=NOW() WHERE id=$1`, inviteID); e != nil {
			return Member{}, e
		}
	}
	key := uuid.New()
	_, e = tx.Exec(ctx, `INSERT INTO users(uuid,name,telegram_id,kind,enrollment_source,enrolled_at,member_pending) VALUES($1,$2,$3,'vless',$4,NOW(),true)`, key.String(), name, id, source)
	if e != nil {
		return Member{}, e
	}
	_, e = tx.Exec(ctx, `INSERT INTO vpn_member_audit(actor,member_id,action) VALUES($1,$1,'registered')`, id)
	if e != nil {
		return Member{}, e
	}
	_, e = tx.Exec(ctx, `INSERT INTO vpn_member_notifications(member_id,admin_id) SELECT $1,telegram_id FROM bot_admins ON CONFLICT DO NOTHING`, id)
	if e != nil {
		return Member{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return Member{}, e
	}
	return r.Get(ctx, id)
}

func (r *MemberRepo) Audit(ctx context.Context, actor, id int64, action string) error {
	return r.db.orm.WithContext(ctx).Table("vpn_member_audit").Create(map[string]any{"actor": actor, "member_id": id, "action": action}).Error
}

// Snapshot identifies exactly which desired versions a successful application acknowledges.
func (r *MemberRepo) Snapshot(ctx context.Context) (map[string]int64, error) {
	var rows []struct {
		UUID           string
		MemberRevision int64
	}
	if err := r.db.orm.WithContext(ctx).Table("users").Select("uuid", "member_revision").Where("member_pending").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, row := range rows {
		out[row.UUID] = row.MemberRevision
	}
	return out, nil
}
func (r *MemberRepo) Acknowledge(ctx context.Context, snapshot map[string]int64) error {
	for id, revision := range snapshot {
		if e := r.db.orm.WithContext(ctx).Table("users").Where("uuid = ? AND member_revision = ?", id, revision).Update("member_pending", false).Error; e != nil {
			return e
		}
	}
	return nil
}
func (r *MemberRepo) SetActive(ctx context.Context, id, actor int64, active bool) error {
	tx, e := r.db.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	result, e := tx.Exec(ctx, `UPDATE users SET is_active=$2,disabled_at=CASE WHEN $2 THEN NULL ELSE NOW() END WHERE telegram_id=$1 AND enrollment_source IS NOT NULL`, id, active)
	if e != nil {
		return e
	}
	if result.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	action := "disabled"
	if active {
		action = "enabled"
	}
	_, e = tx.Exec(ctx, `INSERT INTO vpn_member_audit(actor,member_id,action) VALUES($1,$2,$3)`, actor, id, action)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}

// ExpectedUUID makes an uncertain reset retry safe: an already replaced UUID is not rotated again.
func (r *MemberRepo) Reset(ctx context.Context, id, actor int64, expected string) error {
	if expected == "" {
		return ErrEnrollmentDenied
	}
	tx, e := r.db.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, id); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(817365007)`); e != nil {
		return e
	}
	var current string
	e = tx.QueryRow(ctx, `SELECT uuid::text FROM users WHERE telegram_id=$1 AND enrollment_source IS NOT NULL FOR UPDATE`, id).Scan(&current)
	if e != nil {
		return e
	}
	if current != expected {
		return tx.Commit(ctx)
	}
	nextID := uuid.New()
	next := nextID.String()
	if _, e = NewUserRepo(r.db).rotateUUIDTx(ctx, tx, current, next); e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO vpn_member_audit(actor,member_id,action) VALUES($1,$2,'reset')`, actor, id)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
