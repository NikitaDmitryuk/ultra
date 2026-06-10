-- name: IsBotAdmin :one
SELECT EXISTS(SELECT 1 FROM bot_admins WHERE telegram_id=$1);

-- name: UpsertBotAdmin :exec
INSERT INTO bot_admins(telegram_id, telegram_name) VALUES($1, $2)
ON CONFLICT(telegram_id) DO UPDATE SET telegram_name=$2;

-- name: ListBotAdmins :many
SELECT telegram_id, telegram_name, added_at FROM bot_admins ORDER BY added_at;

-- name: RemoveBotAdmin :exec
DELETE FROM bot_admins WHERE telegram_id=$1;

-- name: HasAnyBotAdmin :one
SELECT EXISTS(SELECT 1 FROM bot_admins);

-- name: CreateInviteToken :exec
INSERT INTO bot_invite_tokens(token) VALUES($1);

-- name: GetInviteTokenUsedBy :one
SELECT used_by FROM bot_invite_tokens WHERE token=$1;

-- name: MarkInviteTokenUsed :exec
UPDATE bot_invite_tokens SET used_by=$1, used_at=NOW() WHERE token=$2;
