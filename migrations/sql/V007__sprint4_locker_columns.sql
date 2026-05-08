-- V007: Extend blob_versions for S3 storage; add sync and nomination columns to nominee_assignments

-- blob_versions: release the NOT NULL constraint on the in-DB ciphertext fields (Sprint 4 stores blobs on S3)
ALTER TABLE blob_versions ALTER COLUMN ciphertext_b64 DROP NOT NULL;
ALTER TABLE blob_versions ALTER COLUMN nonce_b64      DROP NOT NULL;
ALTER TABLE blob_versions ALTER COLUMN auth_tag_b64   DROP NOT NULL;

-- blob_versions: add S3 storage columns (nullable so existing rows are unaffected)
ALTER TABLE blob_versions ADD COLUMN s3_key              TEXT;
ALTER TABLE blob_versions ADD COLUMN size_bytes          BIGINT;
ALTER TABLE blob_versions ADD COLUMN content_hash_sha256 TEXT;
ALTER TABLE blob_versions ADD COLUMN locker_id           TEXT REFERENCES locker_meta (locker_id);
ALTER TABLE blob_versions ADD COLUMN updated_at          TIMESTAMPTZ;

-- nominee_assignments: add nomination tracking and WatermelonDB sync columns
ALTER TABLE nominee_assignments ADD COLUMN official_nomination_status TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE nominee_assignments ADD COLUMN display_order              INTEGER NOT NULL DEFAULT 0;
ALTER TABLE nominee_assignments ADD COLUMN notes                      TEXT;
ALTER TABLE nominee_assignments ADD COLUMN created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE nominee_assignments ADD COLUMN updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE TRIGGER trg_nominee_assignments_updated_at
    BEFORE UPDATE ON nominee_assignments FOR EACH ROW EXECUTE FUNCTION set_updated_at();
