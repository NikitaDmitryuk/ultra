package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type AdminAuditRecord struct {
	ID         int64
	TelegramID int64
	Action     string
	TargetUUID *string
	Payload    map[string]any
	CreatedAt  time.Time
}

func (r *TelegramRepo) LogAdminAction(
	ctx context.Context,
	telegramID int64,
	action string,
	targetUUID *string,
	payload map[string]any,
) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = r.db.Pool.Exec(ctx, `
		INSERT INTO admin_audit_log(telegram_id, action, target_uuid, payload)
		VALUES($1, $2, $3, $4)
	`, telegramID, action, targetUUID, raw)
	return err
}

func (r *TelegramRepo) ListAdminAudit(
	ctx context.Context,
	limit int,
	telegramID *int64,
	action string,
) ([]AdminAuditRecord, error) {
	q := `
		SELECT id, telegram_id, action, target_uuid, payload, created_at
		FROM admin_audit_log
	`
	var where []string
	var args []any
	idx := 1
	if telegramID != nil {
		where = append(where, fmt.Sprintf("telegram_id=$%d", idx))
		args = append(args, *telegramID)
		idx++
	}
	action = strings.TrimSpace(action)
	if action != "" {
		where = append(where, fmt.Sprintf("action=$%d", idx))
		args = append(args, action)
		idx++
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", idx)
	args = append(args, limit)

	rows, err := r.db.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AdminAuditRecord
	for rows.Next() {
		var rec AdminAuditRecord
		var raw []byte
		if err := rows.Scan(&rec.ID, &rec.TelegramID, &rec.Action, &rec.TargetUUID, &raw, &rec.CreatedAt); err != nil {
			return nil, err
		}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &rec.Payload)
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}
