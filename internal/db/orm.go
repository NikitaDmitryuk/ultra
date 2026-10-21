package db

import (
	"database/sql"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// newORM borrows connections from the existing pgx pool. The stdlib adapter has
// no idle connections, so it cannot retain pgx leases and starve SQLC users.
// Schema changes belong exclusively to the numbered migrations.
func newORM(pool *pgxpool.Pool) (*gorm.DB, *sql.DB, error) {
	adapter := stdlib.OpenDBFromPool(pool)
	orm, err := gorm.Open(postgres.New(postgres.Config{Conn: adapter}), &gorm.Config{
		DisableAutomaticPing:   true,
		SkipDefaultTransaction: true,
		Logger:                 logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		_ = adapter.Close()
		return nil, nil, err
	}
	return orm, adapter, nil
}
