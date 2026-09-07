CREATE TABLE subscription_tokens (
 user_uuid UUID PRIMARY KEY REFERENCES users(uuid) ON DELETE CASCADE,
 token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32)
);
