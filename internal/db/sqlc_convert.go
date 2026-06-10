package db

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func toPGUUID(s string) (pgtype.UUID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return pgtype.UUID{}, err
	}
	return pgtype.UUID{Bytes: id, Valid: true}, nil
}

func toPGUUIDPtr(s *string) (pgtype.UUID, error) {
	if s == nil {
		return pgtype.UUID{}, nil
	}
	return toPGUUID(*s)
}

func mustPGUUID(s string) pgtype.UUID {
	id, err := toPGUUID(s)
	if err != nil {
		panic(fmt.Sprintf("invalid uuid %q: %v", s, err))
	}
	return id
}

func fromPGUUID(id pgtype.UUID) string {
	if !id.Valid {
		return ""
	}
	return uuid.UUID(id.Bytes).String()
}

func ptrFromPGUUID(id pgtype.UUID) *string {
	if !id.Valid {
		return nil
	}
	v := fromPGUUID(id)
	return &v
}

func toPGText(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: true}
}

func fromPGText(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return t.String
}

func toPGInt4(n int32) pgtype.Int4 {
	return pgtype.Int4{Int32: n, Valid: true}
}

func ptrFromPGInt4(n pgtype.Int4) *int {
	if !n.Valid {
		return nil
	}
	v := int(n.Int32)
	return &v
}

func ptrFromPGTime(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	return &t.Time
}

func timeFromPG(t pgtype.Timestamptz) time.Time {
	if !t.Valid {
		return time.Time{}
	}
	return t.Time
}

func toPGTime(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func toPGTimePtr(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{}
	}
	return toPGTime(*t)
}

func toPGInterval(d time.Duration) pgtype.Interval {
	return pgtype.Interval{Microseconds: d.Microseconds(), Valid: true}
}

func parseIPAddr(s string) (netip.Addr, error) {
	return netip.ParseAddr(s)
}
