-- Service access is tied to the immutable accounting owner, not a disposable UUID.
CREATE TABLE service_access (
 name TEXT PRIMARY KEY CHECK (name = 'monitor'),
 account_id UUID NOT NULL UNIQUE REFERENCES traffic_accounts(account_id),
 targets TEXT[] NOT NULL CHECK (cardinality(targets) > 0),
 monthly_bytes BIGINT NOT NULL DEFAULT 5368709120 CHECK (monthly_bytes = 5368709120)
);
