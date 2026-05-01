-- Locker metadata: one per creator user
CREATE TABLE locker_meta (
    locker_id        TEXT        NOT NULL,
    user_id          TEXT        NOT NULL,
    completeness_pct INTEGER     NOT NULL DEFAULT 0,
    online_pct       INTEGER     NOT NULL DEFAULT 0,
    offline_pct      INTEGER     NOT NULL DEFAULT 0,
    blob_built       BOOLEAN     NOT NULL DEFAULT FALSE,
    last_saved_at    TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT locker_meta_pkey     PRIMARY KEY (locker_id),
    CONSTRAINT locker_meta_user_fk  FOREIGN KEY (user_id) REFERENCES users (user_id),
    CONSTRAINT locker_meta_user_unq UNIQUE (user_id),
    CONSTRAINT locker_pct_chk       CHECK (completeness_pct BETWEEN 0 AND 100)
);
CREATE TRIGGER trg_locker_meta_updated_at
    BEFORE UPDATE ON locker_meta FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Asset index: one row per asset category per locker
CREATE TABLE asset_index (
    asset_id      TEXT              NOT NULL,
    locker_id     TEXT              NOT NULL,
    category_code TEXT              NOT NULL,
    asset_type    asset_type_enum   NOT NULL,
    status        asset_status_enum NOT NULL DEFAULT 'empty',
    created_at    TIMESTAMPTZ       NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ       NOT NULL DEFAULT NOW(),
    CONSTRAINT asset_index_pkey         PRIMARY KEY (asset_id),
    CONSTRAINT asset_index_locker_fk    FOREIGN KEY (locker_id) REFERENCES locker_meta (locker_id),
    CONSTRAINT asset_index_category_unq UNIQUE (locker_id, category_code)
);
CREATE TRIGGER trg_asset_index_updated_at
    BEFORE UPDATE ON asset_index FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Blob versions: encrypted asset content, one current per asset
CREATE TABLE blob_versions (
    blob_id        TEXT        NOT NULL,
    asset_id       TEXT        NOT NULL,
    ciphertext_b64 TEXT        NOT NULL,
    nonce_b64      TEXT        NOT NULL,
    auth_tag_b64   TEXT        NOT NULL,
    schema_version INTEGER     NOT NULL DEFAULT 1,
    is_current     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT blob_versions_pkey     PRIMARY KEY (blob_id),
    CONSTRAINT blob_versions_asset_fk FOREIGN KEY (asset_id) REFERENCES asset_index (asset_id)
);
CREATE UNIQUE INDEX idx_blob_versions_current
    ON blob_versions (asset_id) WHERE is_current = TRUE;

-- Nominee assignments: soft-deleted via removed_at
CREATE TABLE nominee_assignments (
    assignment_id TEXT        NOT NULL,
    asset_id      TEXT        NOT NULL,
    locker_id     TEXT        NOT NULL,
    nominee_id    TEXT        NOT NULL,
    assigned_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    removed_at    TIMESTAMPTZ,
    CONSTRAINT nominee_assignments_pkey      PRIMARY KEY (assignment_id),
    CONSTRAINT nominee_assignments_asset_fk  FOREIGN KEY (asset_id)   REFERENCES asset_index (asset_id),
    CONSTRAINT nominee_assignments_locker_fk FOREIGN KEY (locker_id)  REFERENCES locker_meta (locker_id),
    CONSTRAINT nominee_assignments_nom_fk    FOREIGN KEY (nominee_id) REFERENCES nominees (nominee_id)
);
CREATE INDEX idx_nominee_assignments_asset   ON nominee_assignments (asset_id)   WHERE removed_at IS NULL;
CREATE INDEX idx_nominee_assignments_nominee ON nominee_assignments (nominee_id) WHERE removed_at IS NULL;
