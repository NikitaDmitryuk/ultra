-- Migration 22 was also used by a historical deployment for unrelated DDL.
-- migrate.go performs a structural verification and, only when the reliability
-- extension is entirely absent, atomically reuses the canonical 022 SQL before
-- recording this version. Partial extensions fail without modifying any data.
SELECT 1;
