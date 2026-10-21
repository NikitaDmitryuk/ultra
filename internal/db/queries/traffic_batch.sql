-- name: InsertBatchTrafficAccounts :exec
WITH input AS (
 SELECT (value->>'account_id')::uuid AS account_id,value->>'exit_id' AS exit_id,
 value->>'exit_tag' AS exit_tag,value->>'period' AS period,
 (value->>'uplink_bytes')::bigint AS uplink_bytes,(value->>'downlink_bytes')::bigint AS downlink_bytes,
 (value->>'charge_total_bytes')::bigint AS charge_total_bytes
 FROM jsonb_array_elements(sqlc.arg(samples)::jsonb)
), collected AS (SELECT sqlc.arg(collected_at)::timestamptz AS at)
INSERT INTO traffic_accounts(account_id)
 SELECT DISTINCT account_id FROM input ON CONFLICT DO NOTHING;

-- name: UpsertBatchAccountUsage :exec
WITH input AS (
 SELECT (value->>'account_id')::uuid AS account_id,value->>'exit_id' AS exit_id,
 value->>'exit_tag' AS exit_tag,value->>'period' AS period,
 (value->>'uplink_bytes')::bigint AS uplink_bytes,(value->>'downlink_bytes')::bigint AS downlink_bytes,
 (value->>'charge_total_bytes')::bigint AS charge_total_bytes
 FROM jsonb_array_elements(sqlc.arg(samples)::jsonb)
), collected AS (SELECT sqlc.arg(collected_at)::timestamptz AS at)
INSERT INTO account_exit_usage(account_id,exit_id,period,uplink_bytes,downlink_bytes,charged_bytes)
 SELECT account_id,exit_id,period,SUM(uplink_bytes)::bigint,SUM(downlink_bytes)::bigint,MAX(charge_total_bytes)
 FROM input GROUP BY account_id,exit_id,period
 ON CONFLICT(account_id,exit_id,period) DO UPDATE SET
 uplink_bytes=account_exit_usage.uplink_bytes+EXCLUDED.uplink_bytes,
 downlink_bytes=account_exit_usage.downlink_bytes+EXCLUDED.downlink_bytes,
 charged_bytes=GREATEST(account_exit_usage.charged_bytes,EXCLUDED.charged_bytes);

-- name: InsertBatchRawTraffic :exec
WITH input AS (
 SELECT (value->>'account_id')::uuid AS account_id,value->>'exit_id' AS exit_id,
 value->>'exit_tag' AS exit_tag,value->>'period' AS period,
 (value->>'uplink_bytes')::bigint AS uplink_bytes,(value->>'downlink_bytes')::bigint AS downlink_bytes,
 (value->>'charge_total_bytes')::bigint AS charge_total_bytes
 FROM jsonb_array_elements(sqlc.arg(samples)::jsonb)
), collected AS (SELECT sqlc.arg(collected_at)::timestamptz AS at)
INSERT INTO traffic_stats(user_uuid,exit_tag,collected_at,uplink_bytes,downlink_bytes)
 SELECT u.uuid,s.exit_tag,c.at,SUM(s.uplink_bytes)::bigint,SUM(s.downlink_bytes)::bigint
 FROM input s JOIN users u USING(account_id) CROSS JOIN collected c
 WHERE s.uplink_bytes>0 OR s.downlink_bytes>0 GROUP BY u.uuid,s.exit_tag,c.at;

-- name: UpsertBatchDailyTraffic :exec
WITH input AS (
 SELECT (value->>'account_id')::uuid AS account_id,value->>'exit_id' AS exit_id,
 value->>'exit_tag' AS exit_tag,value->>'period' AS period,
 (value->>'uplink_bytes')::bigint AS uplink_bytes,(value->>'downlink_bytes')::bigint AS downlink_bytes,
 (value->>'charge_total_bytes')::bigint AS charge_total_bytes
 FROM jsonb_array_elements(sqlc.arg(samples)::jsonb)
), collected AS (SELECT sqlc.arg(collected_at)::timestamptz AS at)
INSERT INTO daily_route_traffic(user_uuid,day,exit_tag,uplink_bytes,downlink_bytes)
 SELECT u.uuid,(c.at AT TIME ZONE 'UTC')::date,s.exit_tag,SUM(s.uplink_bytes)::bigint,SUM(s.downlink_bytes)::bigint
 FROM input s JOIN users u USING(account_id) CROSS JOIN collected c
 WHERE s.exit_tag<>'' AND (s.uplink_bytes>0 OR s.downlink_bytes>0)
 GROUP BY u.uuid,(c.at AT TIME ZONE 'UTC')::date,s.exit_tag
 ON CONFLICT(user_uuid,day,exit_tag) DO UPDATE SET
 uplink_bytes=daily_route_traffic.uplink_bytes+EXCLUDED.uplink_bytes,
 downlink_bytes=daily_route_traffic.downlink_bytes+EXCLUDED.downlink_bytes;

-- name: UpsertBatchMonthlyTraffic :exec
WITH input AS (
 SELECT (value->>'account_id')::uuid AS account_id,value->>'exit_id' AS exit_id,
 value->>'exit_tag' AS exit_tag,value->>'period' AS period,
 (value->>'uplink_bytes')::bigint AS uplink_bytes,(value->>'downlink_bytes')::bigint AS downlink_bytes,
 (value->>'charge_total_bytes')::bigint AS charge_total_bytes
 FROM jsonb_array_elements(sqlc.arg(samples)::jsonb)
), collected AS (SELECT sqlc.arg(collected_at)::timestamptz AS at)
INSERT INTO monthly_traffic(user_uuid,year,month,uplink_bytes,downlink_bytes,updated_at)
 SELECT u.uuid,EXTRACT(YEAR FROM c.at AT TIME ZONE 'UTC')::int,EXTRACT(MONTH FROM c.at AT TIME ZONE 'UTC')::int,
 SUM(s.uplink_bytes)::bigint,SUM(s.downlink_bytes)::bigint,NOW()
 FROM input s JOIN users u USING(account_id) CROSS JOIN collected c
 WHERE s.uplink_bytes>0 OR s.downlink_bytes>0 GROUP BY u.uuid,c.at
 ON CONFLICT(user_uuid,year,month) DO UPDATE SET
 uplink_bytes=monthly_traffic.uplink_bytes+EXCLUDED.uplink_bytes,
 downlink_bytes=monthly_traffic.downlink_bytes+EXCLUDED.downlink_bytes,updated_at=NOW();

-- name: LockTrafficRotation :exec
SELECT pg_advisory_xact_lock(817365007);

-- name: InsertTrafficBatchIdentity :execrows
INSERT INTO traffic_batches(node_id,batch_id,digest) VALUES($1,$2,$3) ON CONFLICT DO NOTHING;

-- name: TrafficBatchDigest :one
SELECT digest FROM traffic_batches WHERE node_id=$1 AND batch_id=$2;
