CREATE TABLE revoked_tokens (
    jti        CHAR(36)    NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT revoked_tokens_pkey PRIMARY KEY (jti)
);
CREATE INDEX idx_revoked_tokens_expires ON revoked_tokens (expires_at);
