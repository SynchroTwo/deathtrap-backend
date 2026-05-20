-- V013: Recovery peel-chain ciphertext relay (Sprint A6, B-A6-1).
--
-- The russian-doll recovery requires peeler N+1 to decrypt the OUTPUT of peeler
-- N. Peel previously persisted only intermediate_hash = SHA256(ciphertext) and
-- discarded the ciphertext, and GET /recovery/session/{id} served none — so the
-- chain dead-ended after layer 1. These columns let the backend RELAY the opaque
-- intermediate ciphertext between peelers and serve the layer-1 envelope + the
-- public HKDF salt from session-status.
--
-- Zero-knowledge is preserved: only opaque ciphertext and the public envelope
-- salt are stored — never a key. Additive + idempotent (no drops).

-- Per-peel relayed ciphertext: the output one peeler hands to the next.
ALTER TABLE recovery_peel_events
    ADD COLUMN IF NOT EXISTS intermediate_ciphertext_b64 TEXT;

-- The public top-level envelope salt (recovery_envelope.saltHex per
-- docs/RECOVERY_BLOB_FORMAT.md §4.1): every peeler derives their layer KEK from
-- it, but peelers 2..N never receive the envelope, so the backend must relay it.
-- Public HKDF salt, not key material.
ALTER TABLE recovery_blobs
    ADD COLUMN IF NOT EXISTS salt_hex CHAR(64);

-- The opaque v1 envelope (encryptedBlobB64), stored alongside the S3 copy so the
-- peel relay is fully DB-backed (layer-1 currentEncryptedB64) without an S3 read
-- on the session-status hot path. Bounded by the 32 KB blob limit.
ALTER TABLE recovery_blobs
    ADD COLUMN IF NOT EXISTS encrypted_blob_b64 TEXT;
