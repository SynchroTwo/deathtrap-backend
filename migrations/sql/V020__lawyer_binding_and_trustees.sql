-- V020: Lawyer 1:1 binding on locker_meta + nominee.is_trustee flag (E006 Phase 1a / Deploy A).
--
-- Resolves the latent issue: trigger-service's NotificationService.java:27-28
-- queries `locker_meta.assigned_lawyer_id` but that column did not exist on
-- locker_meta. V020 adds the column properly; the query then works.
--
-- The recovery-service's StoreBlobHandler comment ("there is no creator->lawyer
-- assignment table today") is also retired by this migration — Model A v2
-- blobs will validate lawyer membership against this column when a v1 legacy
-- blob is uploaded with a lawyer layer.
--
-- nominees.is_trustee is the Model A trustee designation (1..3 trustees per
-- creator). For v2 sequential blobs, every layer's partyId must reference a
-- nominee row with is_trustee=TRUE.
--
-- Additive + idempotent. No drops, no data loss.

-- Lawyer 1:1 binding on locker_meta.
ALTER TABLE locker_meta
    ADD COLUMN IF NOT EXISTS assigned_lawyer_id TEXT REFERENCES lawyers(lawyer_id);

CREATE INDEX IF NOT EXISTS idx_locker_meta_assigned_lawyer
    ON locker_meta (assigned_lawyer_id) WHERE assigned_lawyer_id IS NOT NULL;

-- Trustee flag on nominees (Model A only — applies to nominee_id rows that are
-- both inheritors AND trustees; non-trustee nominees still exist for
-- asset-distribution purposes per E006 spec §"Model A — Sequential Trustees").
ALTER TABLE nominees
    ADD COLUMN IF NOT EXISTS is_trustee BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_nominees_trustee
    ON nominees (creator_id) WHERE is_trustee = TRUE;
