package db

import (
	"encoding/json"
	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"time"
)

// These projections describe migrated columns only; GORM never owns the schema.
type userRow struct {
	UUID                 string `gorm:"column:uuid;primaryKey"`
	AccountID            string
	Name                 string
	Kind                 string
	IsActive             bool
	DisabledAt           *time.Time
	SocksUsername        *string
	SocksPassword        *string
	SocksPort            *int
	LeakPolicy           string
	LeakMaxConcurrentIPs *int `gorm:"column:leak_max_concurrent_ips"`
	LeakMaxUniqueIPs24h  *int `gorm:"column:leak_max_unique_ips_24h"`
	PreferredExitID      *string
	EnrollmentSource     *string
}

func (userRow) TableName() string { return "users" }
func (u userRow) user() auth.User {
	out := auth.User{UUID: u.UUID, AccountID: u.AccountID, Name: u.Name, Kind: u.Kind, IsActive: u.IsActive, DisabledAt: u.DisabledAt, SocksPort: u.SocksPort, LeakPolicy: u.LeakPolicy, LeakMaxConcurrentIPs: u.LeakMaxConcurrentIPs, LeakMaxUniqueIPs24h: u.LeakMaxUniqueIPs24h, PreferredExitID: u.PreferredExitID}
	if u.SocksUsername != nil {
		out.SocksUsername = *u.SocksUsername
	}
	if u.SocksPassword != nil {
		out.SocksPassword = *u.SocksPassword
	}
	if out.Kind == "" {
		out.Kind = "vless"
	}
	return out
}

type subscriptionTokenRow struct {
	UserUUID string `gorm:"column:user_uuid;primaryKey"`
}

func (subscriptionTokenRow) TableName() string { return "subscription_tokens" }

type notificationRow struct {
	ID         int64   `gorm:"primaryKey"`
	UserUUID   *string `gorm:"column:user_uuid"`
	TelegramID int64
	Type       string
	Payload    []byte `gorm:"type:jsonb"`
	SentAt     *time.Time
	CreatedAt  time.Time `gorm:"autoCreateTime:false"`
	Attempts   int
}

func (notificationRow) TableName() string { return "notifications" }
func (r notificationRow) notification() Notification {
	n := Notification{ID: r.ID, UserUUID: r.UserUUID, TelegramID: r.TelegramID, Type: r.Type, SentAt: r.SentAt, CreatedAt: r.CreatedAt, Attempts: r.Attempts}
	if len(r.Payload) > 0 {
		_ = json.Unmarshal(r.Payload, &n.Payload)
	}
	return n
}

type leakSignalRow struct {
	ID        int64
	UserUUID  string `gorm:"column:user_uuid"`
	Kind      string
	Score     int
	Detail    []byte    `gorm:"type:jsonb"`
	CreatedAt time.Time `gorm:"autoCreateTime:false"`
}

func (leakSignalRow) TableName() string { return "user_leak_signals" }

type alertStateRow struct {
	DedupeKey            string `gorm:"primaryKey"`
	Type                 string
	Severity             string
	Channel              string
	Status               string
	ConsecutiveFailures  int
	ConsecutiveSuccesses int
	LastSeenAt           time.Time
	LastSentAt           *time.Time
	LastPayload          []byte    `gorm:"type:jsonb"`
	UpdatedAt            time.Time `gorm:"autoUpdateTime:false"`
}

func (alertStateRow) TableName() string { return "alert_state" }
func (r alertStateRow) state() AlertState {
	s := AlertState{DedupeKey: r.DedupeKey, Type: r.Type, Severity: r.Severity, Channel: r.Channel, Status: r.Status, ConsecutiveFailures: r.ConsecutiveFailures, ConsecutiveSuccesses: r.ConsecutiveSuccesses, LastSeenAt: r.LastSeenAt, LastSentAt: r.LastSentAt, UpdatedAt: r.UpdatedAt}
	if len(r.LastPayload) > 0 {
		_ = json.Unmarshal(r.LastPayload, &s.LastPayload)
	}
	return s
}
