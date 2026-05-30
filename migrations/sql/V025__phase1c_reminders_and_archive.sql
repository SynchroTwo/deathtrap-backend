-- V025: E011 Phase 1C Bucket A — reminder + archive timestamp columns on
-- account_closure. Mirrors the contract §2.1.
--
-- V024 already declared archive_s3_prefix + archive_object_count + finalised_at;
-- V025 adds the bucket reference, the per-closure archive-complete flag, and
-- the two reminder-fired timestamps. Reminders are tracked per-closure (single
-- timestamp); nominees added after the timestamp lands miss the reminder by
-- design (Phase 2 polish: move to per-nominee state).
--
-- Additive + idempotent.
--
-- See ClaudeOutput/E011_BACKEND_CONTRACT_PHASE_1C.md §2.1, §6, §7.

ALTER TABLE account_closure
    -- §9.4 + §9.5 reminder idempotency.
    ADD COLUMN IF NOT EXISTS reminder_72h_sent_at    TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS export_reminder_sent_at TIMESTAMPTZ NULL,
    -- §7 archive bucket (prefix already lives in V024.archive_s3_prefix).
    ADD COLUMN IF NOT EXISTS archive_bucket          TEXT        NULL,
    ADD COLUMN IF NOT EXISTS archive_complete_at     TIMESTAMPTZ NULL;

-- §7.1 archive job needs to find finalising closures that have not yet
-- been archived. Partial index keeps the worker tick cheap.
CREATE INDEX IF NOT EXISTS idx_account_closure_pending_archive
    ON account_closure (finalised_at)
    WHERE status = 'finalising' AND archive_complete_at IS NULL;

-- §6.2 72h reminder lookup — pending_objection rows entering the last 72h.
CREATE INDEX IF NOT EXISTS idx_account_closure_reminder_72h_due
    ON account_closure (objection_window_ends_at)
    WHERE status = 'pending_objection' AND reminder_72h_sent_at IS NULL;

-- §6.1 export reminder lookup — closed rows past 7d post-finalise that
-- haven't fired the reminder yet.
CREATE INDEX IF NOT EXISTS idx_account_closure_export_reminder_due
    ON account_closure (finalised_at)
    WHERE status = 'closed' AND export_reminder_sent_at IS NULL;
