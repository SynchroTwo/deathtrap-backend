-- V016: Recovery Blob Format v2 shape marker (E006 Phase 1a / Deploy A).
--
-- Adds the per-blob recovery_shape column and bumps the default spec_version
-- so newly-uploaded blobs default to v2. Existing v1 rows are unaffected and
-- keep working via the lazy-migration read path; new uploads default to v2
-- and must declare recovery_shape explicitly.
--
-- Shape values:
--   'sequential'  — Model A (nested-doll chain, 1..3 trustees, no lawyer layer).
--                    Existing v1 blobs are backfilled to 'sequential' below
--                    since they were implicitly nested-doll in v1.
--   'parallel'    — Model B (N independent wraps, Phase 2 only).
--
-- See docs/RECOVERY_BLOB_FORMAT_V2.md + RECOVERY_SPEC_V2_BACKEND_CHANGES.md
-- and ClaudeOutput/E006_BACKEND_CONTRACT.md §1, §2 for the contract.
--
-- Additive + idempotent. No drops.

-- Bump default for NEW writes (StoreBlobHandler sets explicitly; this is the fallback).
ALTER TABLE recovery_blobs ALTER COLUMN spec_version SET DEFAULT 'v2';

-- New: the user-selected recovery shape for this blob.
ALTER TABLE recovery_blobs
    ADD COLUMN IF NOT EXISTS recovery_shape VARCHAR(16) NOT NULL DEFAULT 'sequential';

ALTER TABLE recovery_blobs
    DROP CONSTRAINT IF EXISTS recovery_blobs_shape_chk;
ALTER TABLE recovery_blobs
    ADD CONSTRAINT recovery_blobs_shape_chk CHECK (recovery_shape IN ('sequential','parallel'));

-- Same on recovery_blob_layers for forensic queries; nullable to avoid forced backfill.
ALTER TABLE recovery_blob_layers
    ADD COLUMN IF NOT EXISTS recovery_shape VARCHAR(16);

CREATE INDEX IF NOT EXISTS idx_recovery_blobs_shape
    ON recovery_blobs (recovery_shape);
