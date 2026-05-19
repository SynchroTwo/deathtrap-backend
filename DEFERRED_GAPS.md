# Deferred Gaps

Backend gaps that are tracked but not yet implemented. Each item lists the
related contract surface, the reason for deferral, and the workaround in place.

## LOCKER_VERSION_CONFLICT — optimistic locking on blob upload

**Status:** error code published, no throw site.

`packages/common-errors/.../ErrorCode.java` defines `LOCKER_VERSION_CONFLICT`
(HTTP 409). `apps/locker-service/.../UploadBlobHandler.java` does not yet check
an `expectedVersion` on incoming `UploadBlobRequest`; concurrent writes from
two devices overwrite each other (last writer wins via the `SUPERSEDE_BLOBS`
update).

**To close:**
- Add `expectedVersion` (nullable int) to `UploadBlobRequest`.
- In the upload transaction, read the current `blob_versions.version` for the
  asset; if `expectedVersion != null && expectedVersion != current`, throw
  `AppException.lockerVersionConflict(expectedVersion, current)`.
- Frontend already maps the code (Sprint A0 stub).

**Target sprint:** locker concurrency hardening (post-A6).

## TRIGGER_INSUFFICIENT_SOURCES — multi-source threshold check

**Status:** error code published, no throw site.

`packages/common-errors/.../ErrorCode.java` defines `TRIGGER_INSUFFICIENT_SOURCES`
(HTTP 400). Trigger evaluation in `apps/trigger-service` currently fires on a
single confirmed source per trigger; there's no policy that requires N-of-M
confirming signals before a death trigger advances to recovery.

**To close:**
- Decide policy (e.g., for `DEATH_EVENT`: require >=2 verified sources from
  distinct `sourceType` values within a time window).
- In `TriggerEventService` / `DeathEventWebhookHandler`, count verified sources
  for the trigger and throw `AppException.triggerInsufficientSources(received,
  required)` when the threshold isn't met before transitioning state.
- Frontend already maps the code (Sprint A0 stub).

**Target sprint:** trigger-policy review (post-A6).

## Salt rotation on passphrase change — NOT planned

**Status:** decided. `party_salts` stays one-row-per-party.

UI Sprint A1.7 (`ChangePassphrase`) was authored on the assumption that
passphrase change rotates the salt as well as the pub/privkey pair. The
backend treats Argon2id salt as immutable: `party_salts` has
`UNIQUE (party_id, party_type)` (see `migrations/sql/V003__create_crypto_tables.sql:10`),
and `ChangePassphraseHandler` only rotates the keypair, never touches the
salt row.

**Rationale.** The Argon2id salt is not a secret; its only job is to
prevent rainbow-table attacks across users and to give the same passphrase
different derived keys per account. Rotating it on passphrase change adds
no security (an attacker who knew the old salt+passphrase had already
broken the account), forces a multi-row migration, and creates a window
during which the active salt and active privkey blob can disagree if
either insert fails. The standard Argon2id usage is one salt per identity,
many derivations.

**UI implication.** Sprint A1.7's `runRegisterCryptoPipeline` call for a
new passphrase should be replaced with a derive-only path: take the
*existing* salt (returned from `LoginResponse.saltHex` and retained in
client memory), derive a fresh `masterKey` from the new passphrase with
that salt, generate a new ECDH keypair, encrypt the new privkey with the
new masterKey, and submit only the new pub/privkey blob fields. The
`ChangePassphraseRequest` DTO already omits salt — no backend change
needed.

**To revisit if:** product decides per-rotation salt is a hard requirement
(e.g., a compliance audit demands it). That would require dropping the
UNIQUE constraint, adding `is_active`/`version` columns to `party_salts`,
versioning the salt SELECT in `LoginHandler`, and rotating the salt row
inside `ChangePassphraseHandler`'s existing transaction.
