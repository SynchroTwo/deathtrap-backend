-- V026: E011 Phase 1C Bucket B — creator-side access notifications.
--
-- - creator_access_notification_log: per-(creator, nominee) running counter
--   for the hourly batched fan-out worker. Always-on logging per §10.1
--   LOCKED (the toggle gates fan-out only, not logging — keeps the recent-
--   access summary in §10.4 available regardless of the setting).
-- - locker_meta.notify_on_nominee_access: per-creator opt-in toggle. Defaults
--   to FALSE per the privacy-first decision.
--
-- Additive + idempotent.
--
-- See ClaudeOutput/E011_BACKEND_CONTRACT_PHASE_1C.md §2.2 + §10.

CREATE TABLE IF NOT EXISTS creator_access_notification_log (
    creator_id        TEXT        NOT NULL,
    nominee_party_id  TEXT        NOT NULL,
    pending_count     INTEGER     NOT NULL DEFAULT 0,
    first_pending_at  TIMESTAMPTZ NULL,
    last_access_at    TIMESTAMPTZ NULL,
    last_notified_at  TIMESTAMPTZ NULL,
    CONSTRAINT can_log_pkey       PRIMARY KEY (creator_id, nominee_party_id),
    CONSTRAINT can_log_creator_fk FOREIGN KEY (creator_id)       REFERENCES users(user_id),
    CONSTRAINT can_log_nominee_fk FOREIGN KEY (nominee_party_id) REFERENCES nominees(nominee_id)
);

-- Hot-path index for the hourly batch worker — only scans rows with pending events.
CREATE INDEX IF NOT EXISTS idx_can_log_pending
    ON creator_access_notification_log (creator_id)
    WHERE pending_count > 0;

ALTER TABLE locker_meta
    ADD COLUMN IF NOT EXISTS notify_on_nominee_access BOOLEAN NOT NULL DEFAULT FALSE;
