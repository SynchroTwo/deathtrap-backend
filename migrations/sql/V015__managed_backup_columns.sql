-- V015: Managed backup opt-in flag (E003 Phase 1).
--
-- Phase 1 ships a user-facing toggle only; no real versioning logic yet.
-- Storage stays at PI-21's current-version-per-category semantics. The
-- column lives on locker_meta because (a) it is operational state alongside
-- blob_built/last_saved_at, (b) there is no separate "creators" table —
-- creators are users with a creator-type identity, and (c) Phase 2's likely
-- additions (last_snapshot_at, snapshot_count, retention_days) are clearly
-- locker-scoped.
--
-- Additive only. Default FALSE = opted-out, which is the correct initial
-- state for every existing locker. Idempotent: IF NOT EXISTS short-circuits.

ALTER TABLE locker_meta
    ADD COLUMN IF NOT EXISTS managed_backup_enabled BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE locker_meta
    ADD COLUMN IF NOT EXISTS managed_backup_enabled_at TIMESTAMPTZ;
