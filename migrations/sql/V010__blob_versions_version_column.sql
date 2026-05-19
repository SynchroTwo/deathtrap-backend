-- V010: Add monotonic version column to blob_versions for A2 client contract
-- and to enable optimistic-lock enforcement (LOCKER_VERSION_CONFLICT).
--
-- Pre-A2 the table only enforced "one current per asset" via a partial
-- unique index on (asset_id) WHERE is_current = TRUE; concurrent writers
-- could clobber each other silently. A2 introduces a client-supplied
-- `expectedVersion` field on upload, and the handler now rejects with
-- LOCKER_VERSION_CONFLICT on a mismatch.

ALTER TABLE blob_versions ADD COLUMN IF NOT EXISTS version INTEGER;

-- Backfill: rank existing rows per asset_id by created_at so the version
-- numbering matches insertion order. Idempotent; running again is a no-op
-- because the WHERE clause only matches NULLs.
UPDATE blob_versions bv
SET version = ranked.rn
FROM (
    SELECT blob_id,
           ROW_NUMBER() OVER (PARTITION BY asset_id ORDER BY created_at, blob_id) AS rn
    FROM blob_versions
) ranked
WHERE bv.blob_id = ranked.blob_id
  AND bv.version IS NULL;

ALTER TABLE blob_versions ALTER COLUMN version SET NOT NULL;
ALTER TABLE blob_versions ALTER COLUMN version SET DEFAULT 1;

CREATE UNIQUE INDEX IF NOT EXISTS idx_blob_versions_asset_version
    ON blob_versions (asset_id, version);
