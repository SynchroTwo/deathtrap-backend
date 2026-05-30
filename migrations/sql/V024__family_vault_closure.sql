-- V024: Family Vault closure flow (E011 Phase 1B, Path Y + Path B).
--
-- Schema additions:
--   * account_closure_status + account_closure_trigger enums.
--   * account_closure table — 3-cert threshold / missed-payment trigger,
--     30-day creator-objection window, archive references.
--   * Partial unique index enforcing at-most-one-open closure per creator.
--   * ALTER confirmation_responses for closure reuse per §11.2:
--       - drop NOT NULL on window_id;
--       - add nullable closure_id FK;
--       - CHECK: exactly one of (window_id, closure_id) is non-null;
--       - drop the old UNIQUE(window_id, party_id) constraint;
--       - replace with two partial unique indexes, one per kind.
--   * closure_export_acknowledgement table — thin per-nominee read log
--     under Path B (server stores only acknowledgements; no .fvpack
--     server-side because FE generates the package client-side).
--
-- See ClaudeOutput/E011_BACKEND_CONTRACT_PHASE_1B.md for the locked spec.
--
-- Additive + idempotent. No drops of existing data.

-- ────────────────────────────────────────────────────────────────────
-- 1) Enums
-- ────────────────────────────────────────────────────────────────────

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'account_closure_status') THEN
        CREATE TYPE account_closure_status AS ENUM (
            'pending_objection',
            'cancelled',
            'finalising',
            'closed'
        );
    END IF;
END$$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'account_closure_trigger') THEN
        CREATE TYPE account_closure_trigger AS ENUM (
            'three_cert_threshold',
            'missed_payment_grace'
        );
    END IF;
END$$;

-- ────────────────────────────────────────────────────────────────────
-- 2) account_closure
-- ────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS account_closure (
    closure_id               TEXT                    NOT NULL,
    creator_id               TEXT                    NOT NULL,
    trigger_kind             account_closure_trigger NOT NULL,
    triggered_at             TIMESTAMPTZ             NOT NULL DEFAULT NOW(),
    trigger_context_json     JSONB                   NOT NULL,
    -- 30-day creator-objection window:
    objection_window_ends_at TIMESTAMPTZ             NOT NULL,
    status                   account_closure_status  NOT NULL DEFAULT 'pending_objection',
    cancelled_at             TIMESTAMPTZ,
    cancelled_by_party_id    TEXT,
    cancelled_reason         TEXT,
    finalised_at             TIMESTAMPTZ,
    -- Archive references — populated by the archive job on finalise.
    archive_s3_prefix        TEXT,
    archive_object_count     INTEGER,
    CONSTRAINT account_closure_pkey               PRIMARY KEY (closure_id),
    CONSTRAINT account_closure_creator_fk         FOREIGN KEY (creator_id)             REFERENCES users(user_id),
    CONSTRAINT account_closure_cancelled_by_fk    FOREIGN KEY (cancelled_by_party_id)  REFERENCES users(user_id),
    CONSTRAINT chk_finalised_after_window
        CHECK (finalised_at IS NULL OR finalised_at >= objection_window_ends_at - INTERVAL '1 hour')
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_account_closure_one_open_per_creator
    ON account_closure (creator_id)
    WHERE status IN ('pending_objection', 'finalising');

CREATE INDEX IF NOT EXISTS idx_account_closure_expiry
    ON account_closure (objection_window_ends_at)
    WHERE status = 'pending_objection';

CREATE INDEX IF NOT EXISTS idx_account_closure_status
    ON account_closure (status);

-- ────────────────────────────────────────────────────────────────────
-- 3) confirmation_responses reuse for closure objections (§11.2)
-- ────────────────────────────────────────────────────────────────────

-- Add nullable closure_id with FK.
ALTER TABLE confirmation_responses
    ADD COLUMN IF NOT EXISTS closure_id TEXT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'confirmation_responses_closure_fk'
          AND table_name = 'confirmation_responses'
    ) THEN
        ALTER TABLE confirmation_responses
            ADD CONSTRAINT confirmation_responses_closure_fk
            FOREIGN KEY (closure_id) REFERENCES account_closure(closure_id);
    END IF;
END$$;

-- Relax NOT NULL on window_id so closure rows can omit it.
ALTER TABLE confirmation_responses
    ALTER COLUMN window_id DROP NOT NULL;

-- Exactly-one-of constraint.
ALTER TABLE confirmation_responses
    DROP CONSTRAINT IF EXISTS confirmation_responses_oneof_chk;
ALTER TABLE confirmation_responses
    ADD CONSTRAINT confirmation_responses_oneof_chk
    CHECK ((window_id IS NOT NULL) <> (closure_id IS NOT NULL));

-- Replace the old UNIQUE (window_id, party_id) with two partial unique indexes —
-- one per kind — so window vs closure responses don't collide.
ALTER TABLE confirmation_responses
    DROP CONSTRAINT IF EXISTS confirmation_responses_unq;

CREATE UNIQUE INDEX IF NOT EXISTS idx_confirmation_responses_window_party
    ON confirmation_responses (window_id, party_id)
    WHERE window_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_confirmation_responses_closure_party
    ON confirmation_responses (closure_id, party_id)
    WHERE closure_id IS NOT NULL;

-- ────────────────────────────────────────────────────────────────────
-- 4) closure_export_acknowledgement — thin per-nominee read log (Path B)
-- ────────────────────────────────────────────────────────────────────

-- Path B: server stores NO .fvpack; FE assembles the package client-side
-- from the archived ciphertext. This table just records which nominee
-- fetched their export manifest and when, for audit + ops visibility.

CREATE TABLE IF NOT EXISTS closure_export_acknowledgement (
    ack_id              TEXT        NOT NULL,
    closure_id          TEXT        NOT NULL,
    recipient_party_id  TEXT        NOT NULL,
    first_fetched_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_fetched_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    fetch_count         INTEGER     NOT NULL DEFAULT 1,
    CONSTRAINT closure_export_ack_pkey         PRIMARY KEY (ack_id),
    CONSTRAINT closure_export_ack_closure_fk   FOREIGN KEY (closure_id)         REFERENCES account_closure(closure_id),
    CONSTRAINT closure_export_ack_recipient_fk FOREIGN KEY (recipient_party_id) REFERENCES nominees(nominee_id),
    CONSTRAINT closure_export_ack_unq          UNIQUE (closure_id, recipient_party_id)
);

CREATE INDEX IF NOT EXISTS idx_closure_export_ack_recipient
    ON closure_export_acknowledgement (recipient_party_id);
