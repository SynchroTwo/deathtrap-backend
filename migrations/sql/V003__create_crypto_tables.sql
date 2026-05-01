-- Party salts: one per party, immutable after creation
CREATE TABLE party_salts (
    salt_id        TEXT            NOT NULL,
    party_id       TEXT            NOT NULL,
    party_type     party_type_enum NOT NULL,
    salt_hex       CHAR(64)        NOT NULL,
    schema_version INTEGER         NOT NULL DEFAULT 1,
    created_at     TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    CONSTRAINT party_salts_pkey      PRIMARY KEY (salt_id),
    CONSTRAINT party_salts_party_unq UNIQUE (party_id, party_type)
);

-- Party public keys: versioned, one active per party enforced by partial unique index
CREATE TABLE party_public_keys (
    pubkey_id       TEXT            NOT NULL,
    party_id        TEXT            NOT NULL,
    party_type      party_type_enum NOT NULL,
    key_type        key_type_enum   NOT NULL,
    public_key_pem  TEXT            NOT NULL,
    key_fingerprint TEXT            NOT NULL,
    version         INTEGER         NOT NULL DEFAULT 1,
    is_active       BOOLEAN         NOT NULL DEFAULT TRUE,
    activated_at    TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    superseded_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    CONSTRAINT party_public_keys_pkey PRIMARY KEY (pubkey_id)
);
CREATE UNIQUE INDEX idx_pubkeys_active_party
    ON party_public_keys (party_id, party_type)
    WHERE is_active = TRUE;
CREATE INDEX idx_pubkeys_party ON party_public_keys (party_id, party_type);

-- Encrypted private key blobs: versioned; server NEVER decrypts these
CREATE TABLE encrypted_privkey_blobs (
    privkey_blob_id TEXT            NOT NULL,
    party_id        TEXT            NOT NULL,
    party_type      party_type_enum NOT NULL,
    pubkey_id       TEXT            NOT NULL,
    ciphertext_b64  TEXT            NOT NULL,
    nonce_b64       TEXT            NOT NULL,
    auth_tag_b64    TEXT            NOT NULL,
    schema_version  INTEGER         NOT NULL DEFAULT 1,
    version         INTEGER         NOT NULL DEFAULT 1,
    is_active       BOOLEAN         NOT NULL DEFAULT TRUE,
    activated_at    TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    superseded_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    CONSTRAINT encrypted_privkey_blobs_pkey   PRIMARY KEY (privkey_blob_id),
    CONSTRAINT encrypted_privkey_blobs_key_fk FOREIGN KEY (pubkey_id)
        REFERENCES party_public_keys (pubkey_id)
);
CREATE UNIQUE INDEX idx_privkey_blobs_active_party
    ON encrypted_privkey_blobs (party_id, party_type)
    WHERE is_active = TRUE;
CREATE INDEX idx_privkey_blobs_party ON encrypted_privkey_blobs (party_id, party_type);
