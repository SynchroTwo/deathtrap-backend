-- V009: Drop users.aadhaar_ref.
-- B13(a): zero-knowledge — registration no longer accepts or stores Aadhaar.
-- eKYC, if introduced later, will be a separate endpoint with its own storage
-- model (hashed UID, ciphertext, etc.) per a future migration.

ALTER TABLE users DROP COLUMN IF EXISTS aadhaar_ref;
