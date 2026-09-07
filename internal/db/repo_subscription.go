package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/jackc/pgx/v5"
)

type SubscriptionRepo struct{ db *DB }

func NewSubscriptionRepo(db *DB) *SubscriptionRepo { return &SubscriptionRepo{db: db} }

// Rotate returns a credential only once. Only its digest is persisted.
func (r *SubscriptionRepo) Rotate(ctx context.Context, id string) (string, error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(secret[:])
	digest := sha256.Sum256([]byte(token))
	result, err := r.db.Pool.Exec(ctx, `INSERT INTO subscription_tokens(user_uuid,token_hash)
 SELECT uuid,$2 FROM users WHERE uuid=$1 AND is_active AND kind='vless'
 ON CONFLICT(user_uuid) DO UPDATE SET token_hash=EXCLUDED.token_hash`, id, digest[:])
	if err != nil {
		return "", err
	}
	if result.RowsAffected() != 1 {
		return "", pgx.ErrNoRows
	}
	return token, nil
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
 WHERE t.token_hash=$1 AND u.is_active AND u.kind='vless'`, digest[:]).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", pgx.ErrNoRows
	}
	return id, err
}
