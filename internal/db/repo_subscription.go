package db

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/NikitaDmitryuk/ultra/internal/subscriptionkey"
	"github.com/jackc/pgx/v5"
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
	defer tx.Rollback(ctx) //nolint:errcheck
	var active bool
	err = tx.QueryRow(ctx, `SELECT is_active AND kind='vless' FROM users WHERE uuid=$1 FOR UPDATE`, id).Scan(&active)
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
	_, err := r.db.Pool.Exec(ctx, `DELETE FROM subscription_tokens WHERE user_uuid=$1`, id)
	return err
}
func (r *SubscriptionRepo) Resolve(ctx context.Context, token string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		return "", pgx.ErrNoRows
	}
	digest := sha256.Sum256([]byte(token))
	var id string
	err = r.db.Pool.QueryRow(ctx, `SELECT u.uuid::text FROM subscription_tokens t JOIN users u ON u.uuid=t.user_uuid
 WHERE t.token_hash=$1 AND u.is_active AND u.kind='vless' AND NOT u.member_pending`, digest[:]).Scan(&id)
	return id, err
}
