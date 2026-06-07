-- Exit nodes for bridge→exit failover (control plane on bridge only).
CREATE TABLE IF NOT EXISTS exit_nodes (
    id           UUID        PRIMARY KEY,
    name         TEXT        NOT NULL,
    address      TEXT        NOT NULL,
    port         INT         NOT NULL CHECK (port > 0 AND port <= 65535),
    tunnel_uuid  TEXT        NOT NULL,
    priority     INT         NOT NULL DEFAULT 100,
    enabled      BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS exit_nodes_tunnel_uuid_uniq ON exit_nodes(tunnel_uuid);
CREATE UNIQUE INDEX IF NOT EXISTS exit_nodes_address_port_enabled_uniq
    ON exit_nodes(address, port) WHERE enabled = TRUE;
