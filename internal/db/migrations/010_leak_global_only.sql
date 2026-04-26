-- Leak detection uses global defaults in code (5 concurrent, 10 unique/24h); no per-user overrides.
-- Force alert-only in DB; clear legacy per-user thresholds.
UPDATE users SET
  leak_max_concurrent_ips = NULL,
  leak_max_unique_ips_24h = NULL,
  leak_policy = 'alert';
