ALTER TABLE exit_nodes
    ADD COLUMN IF NOT EXISTS pinned_peer_cert_sha256 TEXT NOT NULL DEFAULT '';
