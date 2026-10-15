package db

import (
	"encoding/json"
	"time"
)

// Explicit table and column mappings describe the existing migrated schema;
// these models never create tables or register ORM hooks/associations.
type cloudOfferRow struct {
	ID        string `gorm:"column:id;primaryKey;type:uuid"`
	Actor     int64
	ExpiresAt time.Time
	Body      json.RawMessage `gorm:"type:jsonb"`
}

func (cloudOfferRow) TableName() string { return "cloud_offers" }

type cloudOperationRow struct {
	ID           string `gorm:"column:id;primaryKey;type:uuid"`
	State        string
	Body         json.RawMessage `gorm:"type:jsonb"`
	OccupiesSlot bool
	CreatedAt    time.Time `gorm:"autoCreateTime:false"`
}

func (cloudOperationRow) TableName() string { return "cloud_operations" }

type cloudAuditRow struct {
	Actor       int64
	OperationID string `gorm:"column:operation_id;type:uuid"`
	Action      string
}

func (cloudAuditRow) TableName() string { return "cloud_audit" }

type cloudEventRow struct {
	OperationID string `gorm:"column:operation_id;type:uuid"`
	Phase       string
	Outcome     string
	Code        string
	HTTPStatus  int       `gorm:"column:http_status"`
	DurationMS  int64     `gorm:"column:duration_ms"`
	CreatedAt   time.Time `gorm:"autoCreateTime:false"`
}

func (cloudEventRow) TableName() string { return "cloud_operation_events" }
