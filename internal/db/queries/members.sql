-- name: GetMember :one
SELECT uuid::text, telegram_id, name, is_active, enrollment_source, enrolled_at, member_pending,
 preferred_exit_id::text FROM users WHERE telegram_id=$1 AND enrollment_source IS NOT NULL;

-- name: ListMembers :many
SELECT uuid::text, telegram_id, name, is_active, enrollment_source, enrolled_at, member_pending,
 preferred_exit_id::text FROM users WHERE enrollment_source IS NOT NULL ORDER BY enrolled_at;

-- name: GetVPNGroup :one
SELECT chat_id, title, code, enabled FROM vpn_group WHERE singleton=true;

-- name: PutVPNGroup :exec
INSERT INTO vpn_group(singleton,chat_id,title,code,enabled,updated_by) VALUES(true,$1,$2,$3,$4,$5)
ON CONFLICT(singleton) DO UPDATE SET chat_id=EXCLUDED.chat_id,title=EXCLUDED.title,
code=EXCLUDED.code,enabled=EXCLUDED.enabled,updated_by=EXCLUDED.updated_by;

-- name: ListVPNInvites :many
SELECT id,recipient,created_by,created_at,expires_at,used_at,cancelled_at FROM vpn_invites ORDER BY id DESC LIMIT 200;

-- name: CancelVPNInvite :execrows
UPDATE vpn_invites SET cancelled_at=NOW() WHERE id=$1 AND used_at IS NULL AND cancelled_at IS NULL;
