-- V011: Add spec_version to recovery tables for Recovery Blob Format v1.
--
-- See docs/RECOVERY_SPEC_V1_BACKEND_CHANGES.md §2 for the full rationale.
-- The new column lets the backend distinguish v1 blobs from any future
-- format and supports forensic queries during the eventual v2 migration
-- (no earlier than 2027 per BLOB_FORMAT.md §8.4).
--
-- Defaults to 'v1' for forward-compat: any pre-existing rows (none in
-- staging) are tagged as v1, and clients that don't set the field on
-- insert get v1 implicitly. New writes via StoreBlobHandler set the
-- column explicitly from the request body.

ALTER TABLE recovery_blobs
    ADD COLUMN IF NOT EXISTS spec_version VARCHAR(16) NOT NULL DEFAULT 'v1';

CREATE INDEX IF NOT EXISTS idx_recovery_blobs_spec_version
    ON recovery_blobs (spec_version);

ALTER TABLE recovery_blob_layers
    ADD COLUMN IF NOT EXISTS spec_version VARCHAR(16) NOT NULL DEFAULT 'v1';

-- Nullable on peel events because (a) it's pure forensic denormalization,
-- and (b) we don't want a schema evolution to fail historical peels.
ALTER TABLE recovery_peel_events
    ADD COLUMN IF NOT EXISTS spec_version VARCHAR(16);
