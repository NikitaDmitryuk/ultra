package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/stats"
	xraystats "github.com/xtls/xray-core/features/stats"
)

type refreshContextMeter struct{}

func (refreshContextMeter) GetStatsManager() xraystats.Manager                  { return nil }
func (refreshContextMeter) DrainAccountTraffic() map[string]map[string][2]int64 { return nil }

type refreshContextRunner struct {
	*testRuntimeRunner
	validate    func() error
	reloaded    func()
	validations int
}

func (runner *refreshContextRunner) ValidateJSON([]byte) error {
	runner.validations++
	if runner.validate != nil {
		return runner.validate()
	}
	return nil
}
func (runner *refreshContextRunner) ReloadReason(raw []byte, reason string) error {
	err := runner.testRuntimeRunner.ReloadReason(raw, reason)
	if err == nil && runner.reloaded != nil {
		runner.reloaded()
	}
	return err
}

// This exercises real PostgreSQL acknowledgements and the real refresh/commit
// path. loadDatabase requires an explicitly supplied loopback test DB and owns
// a separate schema; production DATABASE_URL must never be supplied to tests.
func TestRuntimeRefreshAcknowledgementContext(t *testing.T) {
	for _, scenario := range []string{"slow-commit", "commit-fails", "parent-canceled-before", "parent-canceled-after", "quota-ack-fails", "quota-ack-deadline"} {
		t.Run(scenario, func(t *testing.T) {
			database := loadDatabase(t)
			r, base, _ := runtimeFixture(t)
			userRepo := db.NewUserRepo(database)
			if _, err := userRepo.Add(context.Background(), "vless", "context-fixture"); err != nil {
				t.Fatal(err)
			}
			nodeRepo := db.NewExitNodeRepo(database)
			node, err := nodeRepo.Add(
				context.Background(),
				exits.AddParams{
					Name:       "context-exit",
					Address:    "127.0.0.1",
					Port:       51001,
					TunnelUUID: "11111111-2222-3333-4444-555555555555",
					Enabled:    config.BoolPtr(true),
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = database.Pool.Exec(context.Background(), `INSERT INTO exit_traffic_budgets(exit_id,monthly_bytes,source) VALUES($1,1048576,'manual')`, node.ID); err != nil {
				t.Fatal(err)
			}
			users, err := auth.NewDBManager(userRepo, nil, r.log)
			if err != nil {
				t.Fatal(err)
			}
			nodes, err := exits.NewManager(nodeRepo, nil, r.log)
			if err != nil {
				t.Fatal(err)
			}
			r.collector = stats.NewDurable(refreshContextMeter{}, db.NewTrafficRepo(database), users, r.state, r.log)
			r.dbPhaseTimeout = 300 * time.Millisecond
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runner := &refreshContextRunner{testRuntimeRunner: base}
			runner.validate = func() error {
				// Longer than the entire initial DB budget, independent of DB speed.
				time.Sleep(2 * r.dbPhaseTimeout)
				if scenario == "commit-fails" {
					return errors.New("fixture validation failed")
				}
				return nil
			}
			if scenario == "parent-canceled-before" {
				cancel()
			}
			if scenario == "parent-canceled-after" {
				runner.reloaded = cancel
			}
			if scenario == "quota-ack-fails" || scenario == "quota-ack-deadline" {
				runner.reloaded = func() {
					body := "RAISE EXCEPTION 'fixture quota acknowledgement rejected';"
					if scenario == "quota-ack-deadline" {
						body = "PERFORM pg_sleep(2);"
					}
					_, err := database.Pool.Exec(
						context.Background(),
						"CREATE FUNCTION reject_context_quota_ack() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.applied THEN "+body+" END IF; RETURN NEW; END $$; CREATE TRIGGER reject_context_quota_ack BEFORE UPDATE ON user_exit_quotas FOR EACH ROW EXECUTE FUNCTION reject_context_quota_ack()",
					)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			r.runner = runner
			started := time.Now()
			err = r.refresh(ctx, database, users, nodes)
			if scenario == "slow-commit" {
				if err != nil {
					t.Fatalf("acknowledgement inherited expired DB deadline after local commit: %v", err)
				}
				if time.Since(started) <= r.dbPhaseTimeout {
					t.Fatal("fixture did not exceed initial DB deadline")
				}
			} else if err == nil {
				t.Fatal("failed or canceled commit falsely acknowledged")
			}
			if scenario == "quota-ack-deadline" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("acknowledgement lost its own bounded deadline: %v", err)
			}
			if scenario == "parent-canceled-before" || scenario == "parent-canceled-after" {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("parent cancellation lost: %v", err)
				}
			}
			var quotaRows, quotaApplied, routeApplied int
			if err = database.Pool.QueryRow(context.Background(), `SELECT COUNT(*),COUNT(*) FILTER(WHERE applied) FROM user_exit_quotas`).Scan(&quotaRows, &quotaApplied); err != nil {
				t.Fatal(err)
			}
			if err = database.Pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM vpn_locations WHERE applied`).Scan(&routeApplied); err != nil {
				t.Fatal(err)
			}
			if scenario == "slow-commit" {
				if quotaRows != 1 || quotaApplied != 1 || routeApplied != 1 {
					t.Fatalf("successful local commit not fully acknowledged: quota=%d/%d route=%d", quotaApplied, quotaRows, routeApplied)
				}
			} else if quotaApplied != 0 || routeApplied != 0 {
				t.Fatalf("failed path falsely applied: quota=%d route=%d", quotaApplied, routeApplied)
			}
			if scenario == "parent-canceled-before" && runner.validations != 0 {
				t.Fatal("canceled parent reached local commit")
			}
		})
	}
}
