-- V008: Align recovery tables with Sprint 6 handler code.
-- V005 was designed for an older API shape; all six recovery tables need structural changes.

-- 1. recovery_blobs: add s3_key and built_at (handler inserts both)
ALTER TABLE recovery_blobs ADD COLUMN IF NOT EXISTS s3_key   TEXT;
ALTER TABLE recovery_blobs ADD COLUMN IF NOT EXISTS built_at TIMESTAMPTZ;

-- 2. recovery_blob_layers: swap ciphertext columns for party/key columns
ALTER TABLE recovery_blob_layers DROP COLUMN IF EXISTS ciphertext_b64;
ALTER TABLE recovery_blob_layers DROP COLUMN IF EXISTS nonce_b64;
ALTER TABLE recovery_blob_layers DROP COLUMN IF EXISTS auth_tag_b64;
ALTER TABLE recovery_blob_layers ADD COLUMN IF NOT EXISTS party_id      TEXT;
ALTER TABLE recovery_blob_layers ADD COLUMN IF NOT EXISTS party_type    TEXT;
ALTER TABLE recovery_blob_layers ADD COLUMN IF NOT EXISTS pubkey_id     TEXT;
ALTER TABLE recovery_blob_layers ADD COLUMN IF NOT EXISTS key_fingerprint TEXT;

-- 3. recovery_sessions: drop nominee-centric columns, add handler-expected columns
ALTER TABLE recovery_sessions DROP CONSTRAINT IF EXISTS recovery_sessions_nom_fk;
ALTER TABLE recovery_sessions DROP COLUMN IF EXISTS nominee_id;
ALTER TABLE recovery_sessions DROP COLUMN IF EXISTS layers_peeled;
ALTER TABLE recovery_sessions DROP COLUMN IF EXISTS expires_at;
ALTER TABLE recovery_sessions ADD COLUMN IF NOT EXISTS creator_id   TEXT;
ALTER TABLE recovery_sessions ADD COLUMN IF NOT EXISTS trigger_id   TEXT;
ALTER TABLE recovery_sessions ADD COLUMN IF NOT EXISTS initiated_at TIMESTAMPTZ;
ALTER TABLE recovery_sessions ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
ALTER TABLE recovery_sessions ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ;

-- 4. recovery_peel_events: drop old unique constraint, add party/layer/hash columns
ALTER TABLE recovery_peel_events DROP CONSTRAINT IF EXISTS recovery_peel_events_unq;
ALTER TABLE recovery_peel_events ADD COLUMN IF NOT EXISTS party_id          TEXT;
ALTER TABLE recovery_peel_events ADD COLUMN IF NOT EXISTS party_type        TEXT;
ALTER TABLE recovery_peel_events ADD COLUMN IF NOT EXISTS layer_order       INTEGER;
ALTER TABLE recovery_peel_events ADD COLUMN IF NOT EXISTS intermediate_hash TEXT;
ALTER TABLE recovery_peel_events ADD COLUMN IF NOT EXISTS created_at        TIMESTAMPTZ DEFAULT NOW();

-- 5. blob_rebuild_log: add missing columns, make old_blob_id nullable
ALTER TABLE blob_rebuild_log ALTER COLUMN old_blob_id DROP NOT NULL;
ALTER TABLE blob_rebuild_log ADD COLUMN IF NOT EXISTS rebuild_reason    TEXT;
ALTER TABLE blob_rebuild_log ADD COLUMN IF NOT EXISTS triggered_by      TEXT;
ALTER TABLE blob_rebuild_log ADD COLUMN IF NOT EXISTS triggered_by_type TEXT;
ALTER TABLE blob_rebuild_log ADD COLUMN IF NOT EXISTS created_at        TIMESTAMPTZ DEFAULT NOW();
