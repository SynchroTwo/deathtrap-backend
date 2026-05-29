-- V023: Family Vault Phase 1A (E011 Path Y — read-only for nominees).
--
-- Schema additions:
--   * recovery_mode_enum + locker_meta.recovery_mode  — picks the locker's
--     recovery model (model_a sequential trustees, model_b independent
--     nominees, family_vault shared read-only).
--   * family_vault_wrap_status enum + family_vault_wraps table — per-
--     nominee ECDH wrap of the creator's lockerKey. Server-opaque
--     envelope mirrors recovery_blob_layers shape for FE primitive reuse.
--
-- See ClaudeOutput/E011_BACKEND_CONTRACT.md for the locked spec.
--
-- Additive + idempotent. No drops.

-- ────────────────────────────────────────────────────────────────────
-- 1) recovery_mode_enum on locker_meta
-- ────────────────────────────────────────────────────────────────────

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'recovery_mode_enum') THEN
        CREATE TYPE recovery_mode_enum AS ENUM ('model_a', 'model_b', 'family_vault');
    END IF;
END$$;

ALTER TABLE locker_meta
    ADD COLUMN IF NOT EXISTS recovery_mode recovery_mode_enum;

CREATE INDEX IF NOT EXISTS idx_locker_meta_recovery_mode
    ON locker_meta (recovery_mode) WHERE recovery_mode IS NOT NULL;

-- ────────────────────────────────────────────────────────────────────
-- 2) family_vault_wraps
-- ────────────────────────────────────────────────────────────────────

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'family_vault_wrap_status') THEN
        CREATE TYPE family_vault_wrap_status AS ENUM ('active', 'revoked');
    END IF;
END$$;

CREATE TABLE IF NOT EXISTS family_vault_wraps (
    wrap_id          TEXT                     NOT NULL,
    creator_id       TEXT                     NOT NULL,
    nominee_party_id TEXT                     NOT NULL,
    -- Envelope (server-opaque) — mirrors recovery_blob_layers shape.
    spec_version     TEXT                     NOT NULL,
    salt_hex         CHAR(64)                 NOT NULL,
    key_fingerprint  CHAR(64)                 NOT NULL,
    eph_pubkey_b64   TEXT                     NOT NULL,
    nonce_b64        TEXT                     NOT NULL,
    ciphertext_b64   TEXT                     NOT NULL,
    auth_tag_b64     TEXT                     NOT NULL,
    -- Lifecycle
    status           family_vault_wrap_status NOT NULL DEFAULT 'active',
    created_at       TIMESTAMPTZ              NOT NULL DEFAULT NOW(),
    revoked_at       TIMESTAMPTZ,
    revoked_reason   TEXT,
    CONSTRAINT family_vault_wraps_pkey         PRIMARY KEY (wrap_id),
    CONSTRAINT family_vault_wraps_creator_fk   FOREIGN KEY (creator_id)       REFERENCES users(user_id),
    CONSTRAINT family_vault_wraps_nominee_fk   FOREIGN KEY (nominee_party_id) REFERENCES nominees(nominee_id)
);

-- One ACTIVE wrap per (creator, nominee) pair — revoked rows may stack for audit.
CREATE UNIQUE INDEX IF NOT EXISTS idx_fvw_one_active_per_pair
    ON family_vault_wraps (creator_id, nominee_party_id) WHERE status = 'active';

-- Partial indexes the access-check / fetch paths hit.
CREATE INDEX IF NOT EXISTS idx_fvw_creator_active
    ON family_vault_wraps (creator_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_fvw_nominee_active
    ON family_vault_wraps (nominee_party_id) WHERE status = 'active';
