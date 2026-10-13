package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/db"
)

func ensureStaticBudgets(ctx context.Context, spec *config.Spec, input string) error {
	if spec.Role != config.RoleBridge || spec.Database == nil || spec.Database.DSN == "" || !filepath.IsAbs(input) {
		return errors.New("static budgets require bridge database and absolute input")
	}
	info, err := os.Lstat(input)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 65536 {
		return errors.New("private bounded static budget input required")
	}
	raw, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	var nodes []db.StaticBudgetNode
	if err = json.Unmarshal(raw, &nodes); err != nil {
		return err
	}
	database, err := db.Open(ctx, spec.Database.DSN)
	if err != nil {
		return errors.New("static budget database unavailable")
	}
	defer database.Close()
	if err = db.NewQuotaRepo(database).EnsureStaticBudgets(ctx, nodes); err != nil {
		return err
	}
	fmt.Println(`{"static_budgets":"ready"}`)
	return nil
}
