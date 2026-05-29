-- V019: Confirmation window state machine (E006 Phase 1 / Deploy B Chunk 1).
--
-- Replaces the PI-02 "2-of-N source threshold" auto-promote logic with a
-- social-confirmation + dead-man's-switch flow. Each cert upload either:
--   - starts a new cycle (no prior pending window), or
--   - logs against an existing pending window (additional uploads during
--     window are allowed but don't reset it), or
--   - logs as a Phase 5 "other trustee/nominee" upload after death already
--     confirmed.
--
-- After cancellation (objection or lawyer-silent), a 24h cooloff is enforced
-- before a new cycle can start. The 1-min EventBridge worker (Deploy B
-- Chunk 3) flips pending→confirmed on window expiry (silence=consent for
-- creator+nominees), and pending→lawyer_silent when the lawyer 168h expires.
--
-- See docs ClaudeOutput/E006_BACKEND_CONTRACT.md §1 (V019), §9 (state machine).
--
-- Additive + idempotent. No drops.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'confirmation_status_enum') THEN
        CREATE TYPE confirmation_status_enum AS ENUM (
            'pending',          -- window open, awaiting responses
            'confirmed',        -- window passed or all parties confirmed; ready to release blob
            'objected',         -- cancelled by an objection from creator/nominee/lawyer
            'lawyer_silent',    -- cancelled because lawyer 168h silence
            'expired'           -- window passed without resolution (system error)
        );
    END IF;
END$$;

CREATE TABLE IF NOT EXISTS confirmation_window (
    window_id            TEXT                     NOT NULL,
    creator_id           TEXT                     NOT NULL,
    first_cert_id        TEXT                     NOT NULL,
    cycle_number         INTEGER                  NOT NULL DEFAULT 1,
    window_hours         INTEGER                  NOT NULL,        -- 24..168
    lawyer_designated    BOOLEAN                  NOT NULL DEFAULT FALSE,
    started_at           TIMESTAMPTZ              NOT NULL DEFAULT NOW(),
    expires_at           TIMESTAMPTZ              NOT NULL,        -- started_at + window_hours
    lawyer_expires_at    TIMESTAMPTZ,                              -- started_at + 168h, NULL if no lawyer
    status               confirmation_status_enum NOT NULL DEFAULT 'pending',
    resolution_party_id  TEXT,                                     -- party who clicked confirm/object (NULL if silence-driven)
    resolution_at        TIMESTAMPTZ,
    cancelled_reason     TEXT,                                     -- objection text or 'lawyer_silent_at_168h'
    cooloff_until        TIMESTAMPTZ,                              -- set on cancel: resolution_at + 24h
    CONSTRAINT confirmation_window_pkey       PRIMARY KEY (window_id),
    CONSTRAINT confirmation_window_creator_fk FOREIGN KEY (creator_id)    REFERENCES users(user_id),
    CONSTRAINT confirmation_window_cert_fk    FOREIGN KEY (first_cert_id) REFERENCES death_cert_uploads(cert_id),
    CONSTRAINT confirmation_window_hours_chk  CHECK (window_hours BETWEEN 24 AND 168)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_confirmation_active_creator
    ON confirmation_window (creator_id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_confirmation_window_expires  ON confirmation_window (expires_at);
CREATE INDEX IF NOT EXISTS idx_confirmation_window_status   ON confirmation_window (status);

-- Per-party response rows (one per recipient who clicked confirm/object).
CREATE TABLE IF NOT EXISTS confirmation_responses (
    response_id     TEXT                    NOT NULL,
    window_id       TEXT                    NOT NULL,
    party_id        TEXT                    NOT NULL,
    party_type      party_type_enum         NOT NULL,
    action          TEXT                    NOT NULL,             -- 'confirm' | 'object'
    via_channel     TEXT                    NOT NULL,             -- 'email' | 'sms' | 'push' | 'inapp'
    reason          TEXT,                                         -- optional objection reason
    responded_at    TIMESTAMPTZ             NOT NULL DEFAULT NOW(),
    CONSTRAINT confirmation_responses_pkey    PRIMARY KEY (response_id),
    CONSTRAINT confirmation_responses_win_fk  FOREIGN KEY (window_id) REFERENCES confirmation_window(window_id),
    CONSTRAINT confirmation_responses_action_chk CHECK (action IN ('confirm','object')),
    CONSTRAINT confirmation_responses_unq     UNIQUE (window_id, party_id)
);
