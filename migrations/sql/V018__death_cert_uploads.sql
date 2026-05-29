-- V018: Death certificate uploads (E006 Phase 1 / Deploy B Chunk 1).
--
-- A trustee (Model A) or any nominee (Model B) uploads a soft copy of the
-- creator's death certificate. Stored plaintext at rest in S3 (legal audit
-- requirement) at s3://deathtrap-{env}/death-certs/{creatorId}/{certId},
-- 7-year retention via bucket lifecycle policy (configured at infra layer).
--
-- See docs ClaudeOutput/E006_BACKEND_CONTRACT.md §8.
--
-- Additive + idempotent. No drops.

CREATE TABLE IF NOT EXISTS death_cert_uploads (
    cert_id              TEXT            NOT NULL,
    creator_id           TEXT            NOT NULL,
    uploader_party_id    TEXT            NOT NULL,
    uploader_party_type  party_type_enum NOT NULL,
    s3_key               TEXT            NOT NULL,
    mime_type            TEXT            NOT NULL,
    size_bytes           BIGINT          NOT NULL,
    content_hash_sha256  CHAR(64)        NOT NULL,
    uploaded_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    CONSTRAINT death_cert_uploads_pkey       PRIMARY KEY (cert_id),
    CONSTRAINT death_cert_uploads_creator_fk FOREIGN KEY (creator_id) REFERENCES users(user_id),
    CONSTRAINT death_cert_size_chk           CHECK (size_bytes > 0 AND size_bytes <= 10485760),
    CONSTRAINT death_cert_mime_chk           CHECK (mime_type IN ('image/jpeg','image/png','application/pdf'))
);
CREATE INDEX IF NOT EXISTS idx_death_cert_uploads_creator  ON death_cert_uploads (creator_id);
CREATE INDEX IF NOT EXISTS idx_death_cert_uploads_uploaded ON death_cert_uploads (uploaded_at);
