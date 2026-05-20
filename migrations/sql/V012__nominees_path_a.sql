-- V012: Nominee schema for Sprint A3 "path A" (client-signed invite tokens).
--
-- The deployed nominees table was designed for the server-issued-token flow
-- (invite_token_hash + relationship + registration_order). A3 switches to
-- self-contained, creator-signed ECDSA invite tokens: the backend verifies
-- the signature against the creator's stored pubkey on accept, so it no
-- longer stores a token hash. See docs (RECOVERY/A3) + NomineeAcceptHandler.
--
-- Changes are additive + constraint relaxations only. No drops, no data loss.

-- A3's Nominee allows null email/mobile and drops "relationship".
ALTER TABLE nominees ALTER COLUMN mobile DROP NOT NULL;
ALTER TABLE nominees ALTER COLUMN email DROP NOT NULL;
ALTER TABLE nominees ALTER COLUMN relationship DROP NOT NULL;

-- Lifecycle timestamps surfaced in the UI's Nominee type (invitedAt maps to
-- the existing created_at).
ALTER TABLE nominees ADD COLUMN IF NOT EXISTS registered_at TIMESTAMPTZ;
ALTER TABLE nominees ADD COLUMN IF NOT EXISTS removed_at    TIMESTAMPTZ;

-- Audit: SHA-256 of the canonical invite-token payload that was accepted.
-- Lets us detect/refuse a second accept with a different payload for the
-- same nominee_id.
ALTER TABLE nominees ADD COLUMN IF NOT EXISTS invite_payload_hash CHAR(64);

-- Records the last time the creator hit POST /auth/nominees/:id/resend.
-- The token itself is regenerated client-side; this is just for audit/UX.
ALTER TABLE nominees ADD COLUMN IF NOT EXISTS last_resend_at TIMESTAMPTZ;
