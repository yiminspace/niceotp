CREATE TABLE accounts (
    id UUID PRIMARY KEY,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    UNIQUE (issuer, subject)
);
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE vaults (
    account_id UUID PRIMARY KEY REFERENCES accounts(id),
    header JSONB NOT NULL,
    header_revision BIGINT NOT NULL DEFAULT 1,
    cursor BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE items (
    account_id UUID NOT NULL REFERENCES vaults(account_id),
    id UUID NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    payload JSONB,
    PRIMARY KEY (account_id, id)
);
CREATE INDEX items_cursor ON items (account_id, revision);
CREATE TABLE mutations (
    account_id UUID NOT NULL REFERENCES vaults(account_id),
    id UUID NOT NULL,
    request JSONB NOT NULL,
    revision BIGINT NOT NULL,
    PRIMARY KEY (account_id, id)
);
