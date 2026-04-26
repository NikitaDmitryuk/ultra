-- Per-user kind (vless vs dedicated SOCKS5 inbound) and SOCKS credentials for kind=socks5.
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'vless',
  ADD COLUMN IF NOT EXISTS socks_username TEXT,
  ADD COLUMN IF NOT EXISTS socks_password TEXT,
  ADD COLUMN IF NOT EXISTS socks_port INT;

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_kind_check;
ALTER TABLE users ADD CONSTRAINT users_kind_check CHECK (kind IN ('vless', 'socks5'));

CREATE UNIQUE INDEX IF NOT EXISTS users_socks_port_uniq ON users(socks_port) WHERE socks_port IS NOT NULL;
