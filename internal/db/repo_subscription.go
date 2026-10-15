package db

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/NikitaDmitryuk/ultra/internal/subscriptionkey"
	"github.com/jackc/pgx/v5"
	"gorm.io/gorm"
)

var ErrLegacySubscription = errors.New("legacy subscription requires explicit rotation")

type SubscriptionRepo struct {
	db   *DB
	keys *subscriptionkey.Ring
}

func NewSubscriptionRepo(db *DB, keys ...*subscriptionkey.Ring) *SubscriptionRepo {
	r := &SubscriptionRepo{db: db}
	if len(keys) > 0 {
		r.keys = keys[0]
	}
	return r
}
func (r *SubscriptionRepo) Ready() bool { _, _, e := r.keys.Seal("availability", ""); return e == nil }

// GetOrCreate recovers a stable link. Legacy hash-only credentials are never silently replaced.
func (r *SubscriptionRepo) GetOrCreate(ctx context.Context, id string) (string, error) {
	return r.issue(ctx, id, false)
}
func (r *SubscriptionRepo) Rotate(ctx context.Context, id string) (string, error) {
	return r.issue(ctx, id, true)
}
func (r *SubscriptionRepo) issue(ctx context.Context, id string, rotate bool) (string, error) {
	if !r.Ready() {
		return "", subscriptionkey.ErrUnavailable
	}
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }() //nolint:errcheck
	var active bool
	err = tx.QueryRow(ctx, `SELECT is_active AND kind='vless' AND NOT EXISTS(SELECT 1 FROM service_access s WHERE s.account_id=users.account_id) FROM users WHERE uuid=$1 FOR UPDATE`, id).Scan(&active)
	if err != nil {
		return "", err
	}
	if !active {
		return "", pgx.ErrNoRows
	}
	if !rotate {
		var encrypted []byte
		var version *string
		err = tx.QueryRow(ctx, `SELECT encrypted_token,key_version FROM subscription_tokens WHERE user_uuid=$1`, id).Scan(&encrypted, &version)
		if err == nil {
			if version == nil || len(encrypted) == 0 {
				return "", ErrLegacySubscription
			}
			token, e := r.keys.Open(id, encrypted, *version)
			if e != nil {
				return "", e
			}
			return token, tx.Commit(ctx)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return "", err
		}
	}
	token, err := NewOpaqueToken()
	if err != nil {
		return "", err
	}
	encrypted, version, err := r.keys.Seal(id, token)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(token))
	_, err = tx.Exec(ctx, `INSERT INTO subscription_tokens(user_uuid,token_hash,encrypted_token,key_version) VALUES($1,$2,$3,$4)
 ON CONFLICT(user_uuid) DO UPDATE SET token_hash=EXCLUDED.token_hash,encrypted_token=EXCLUDED.encrypted_token,key_version=EXCLUDED.key_version`, id, digest[:], encrypted, version)
	if err != nil {
		return "", err
	}
	return token, tx.Commit(ctx)
}
func (r *SubscriptionRepo) Revoke(ctx context.Context, id string) error {
	return r.db.orm.WithContext(ctx).Table("subscription_tokens").Where("user_uuid = ?", id).Delete(&subscriptionTokenRow{}).Error
}
func (r *SubscriptionRepo) Resolve(ctx context.Context, token string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		return "", pgx.ErrNoRows
	}
	digest := sha256.Sum256([]byte(token))
	var row struct{ UUID string }
	err = cloudLookupError(r.activeTokens(ctx).Select("u.uuid").Where("t.token_hash = ?", digest[:]).Take(&row).Error)
	return row.UUID, err
}

// IsAdminOwner resolves permissions from the subscription owner, never request metadata.
func (r *SubscriptionRepo) IsAdminOwner(ctx context.Context, id string) (bool, error) {
	var rows []struct{ UUID string }
	err := r.db.orm.WithContext(ctx).Table("users AS u").Select("u.uuid").Joins("JOIN bot_admins a ON a.telegram_id = u.telegram_id").Where("u.uuid = ?", id).Limit(1).Find(&rows).Error
	return len(rows) > 0, err
}

// EnqueueIngressNotice deduplicates a rollout notice across retries and concurrent callers.
func (r *SubscriptionRepo) EnqueueIngressNotice(ctx context.Context, key, text string) (int64, error) {
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "ultra-ingress:"+key); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO notifications(user_uuid,telegram_id,type,payload)
 SELECT u.uuid,u.telegram_id,'ingress_migration',jsonb_build_object('text',$2::text,'dedupe_key',$1::text)
 FROM users u JOIN subscription_tokens s ON s.user_uuid=u.uuid
 WHERE u.is_active AND u.kind='vless' AND NOT u.member_pending AND u.telegram_id IS NOT NULL
 AND NOT EXISTS(SELECT 1 FROM notifications n WHERE n.telegram_id=u.telegram_id AND n.type='ingress_migration' AND n.payload->>'dedupe_key'=$1)`, key, text)
	if err != nil {
		return 0, err
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ListActiveTokens decrypts existing eligible subscriptions without issuing any.
// Legacy hash-only tokens cannot be exported and are deliberately skipped.
func (r *SubscriptionRepo) ListActiveTokens(ctx context.Context) ([]string, error) {
	if !r.Ready() {
		return nil, subscriptionkey.ErrUnavailable
	}
	var rows []struct {
		UUID           string
		EncryptedToken []byte
		KeyVersion     string
	}
	e := r.activeTokens(ctx).Select("u.uuid, t.encrypted_token, t.key_version").Where("t.encrypted_token IS NOT NULL AND t.key_version IS NOT NULL").Order("u.uuid").Find(&rows).Error
	if e != nil {
		return nil, e
	}
	out := []string{}
	for _, row := range rows {
		if len(row.EncryptedToken) == 0 {
			continue
		}
		token, e := r.keys.Open(row.UUID, row.EncryptedToken, row.KeyVersion)
		if e != nil {
			return nil, e
		}
		out = append(out, token)
	}
	return out, nil
}

// Build the eligibility predicate once so resolving and exporting tokens agree.
func (r *SubscriptionRepo) activeTokens(ctx context.Context) *gorm.DB {
	services := r.db.orm.Table("service_access AS s").Select("1").Where("s.account_id = u.account_id")
	return r.db.orm.WithContext(ctx).Table("subscription_tokens AS t").Joins("JOIN users u ON u.uuid = t.user_uuid").Where("u.is_active AND u.kind = ? AND NOT u.member_pending", "vless").Where("NOT EXISTS (?)", services)
}
