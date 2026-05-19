# Recovery Spec v1 — Backend Changes Required

> **Status:** REVISION 2 — backend dev agent's ACK-WITH-REVISIONS
> feedback applied. Re-publishing for final ack before PR opens.
> Companion to `RECOVERY_BLOB_FORMAT.md`.
> **Audience:** backend dev agent on `SynchroTwo/deathtrap-backend`.
> **UI side will not implement any v1 code until the final backend
> ack lands**, per the manual checkpoint in our agreed sprint plan.

## Revision history

- **rev 2** (current): all 6 factual corrections applied
  (`recovery_blobs` plural; PK is `blob_id`; current `StoreBlobRequest`
  shape already carries `layers[]` + `rebuildReason`; `pubkey_id`
  dropped from the wire and resolved server-side; field-name
  alignment with `PeelHandler.PeelResponse`; existing peel
  `intermediateCiphertextB64` is freeform). Layer ordering switched
  to 1-indexed throughout. All 10 open questions marked answered.
  Migration ordering simplified — backwards-compat window is no
  longer needed because the deployed shape is already 90% v1. Rate
  limit reuses existing `RATE_LIMITED` code. Config endpoint moved
  to `GET /recovery/config`.
- **rev 1** (superseded): initial draft.

---

## 0. tl;dr

The UI proposes a layered (onion) recovery-blob format using only
the project's existing crypto primitives (ECDH-P256 + HKDF-SHA-256 +
AES-256-GCM). Backend impact (after rev 2):

- **3 new columns** (`spec_version`): `recovery_blobs` (NOT NULL DEFAULT 'v1'),
  `recovery_blob_layers` (NOT NULL DEFAULT 'v1'), `recovery_peel_events`
  (NULLABLE — forensic only).
- **Drop `pubkey_id` from `BlobLayerRequest`** — backend resolves
  active pubkey server-side (one row per party via
  `idx_pubkeys_active_party`).
- **Add `specVersion` field to top-level `StoreBlobRequest`** —
  existing body is otherwise already ~90% the v1 shape, including
  `layers[]` and `rebuildReason`.
- **1 thin new endpoint** `GET /recovery/config` returning
  `{minWriteSpecVersion, currentRecommendedSpecVersion, supportedSpecVersionsForRead}`.
- **8 new validation rules** at upload time (§4) + matching error codes.
- **PeelHandler response field renames** (`layersRemaining` →
  `remainingLayers`, etc. — see §3.2).
- **`StoreBlobHandler` response field rename** (`layerCount` /
  `builtAt` → `version` / `uploadedAt` — see §3.1).
- **Rate limit on uploads** — reuse existing `RATE_LIMITED` code.
- **No deletes, no destructive migration, no backwards-compat window
  needed.**

Nothing about the encryption scheme itself touches the backend —
backend continues to store opaque bytes and never inspects them.

## 1. What is NOT changing on the backend

To set expectations early — these are explicitly out of scope of v1:

- **No encryption / decryption on the server.** Backend never touches
  plaintext. The blob arrives opaque, leaves opaque.
- **No key material on the server.** Recipient pubkeys are already
  stored (today); recipient privkeys never reach the server (today,
  and still).
- **No peel-time crypto on the server.** Peel handler continues to
  hash `intermediateCiphertextB64` for audit and ignore content.
- **No protocol-recipe API.** The spec lives in the client code.
  Backend only advertises the minimum write version it will accept
  (a refuse-to-act gate, not a recipe). Rationale in
  `RECOVERY_BLOB_FORMAT.md` §8.3.

## 2. Schema changes

### 2.1 `recovery_blobs` — add `spec_version`

```sql
-- migration V011_add_recovery_spec_version.sql
ALTER TABLE recovery_blobs
  ADD COLUMN spec_version VARCHAR(16) NOT NULL DEFAULT 'v1';

CREATE INDEX idx_recovery_blobs_spec_version
  ON recovery_blobs (spec_version);
```

- Table name is `recovery_blobs` (plural). PK is `blob_id`.
- `VARCHAR(16)` accommodates `'v1'`, `'v2'`, `'v1-experimental'`, etc.
- Default `'v1'` backfills any existing rows (there should be zero in
  staging today since no creator has uploaded a recovery blob).
- Index supports future deprecation queries
  (`WHERE spec_version < 'v2'`).

### 2.2 `recovery_blob_layers` — add `spec_version`

```sql
ALTER TABLE recovery_blob_layers
  ADD COLUMN spec_version VARCHAR(16) NOT NULL DEFAULT 'v1';
```

Same rationale. Denormalized intentionally so per-layer audit
queries don't need a join.

### 2.3 `recovery_peel_events` — `spec_version` (OPTIONAL)

```sql
ALTER TABLE recovery_peel_events
  ADD COLUMN spec_version VARCHAR(16) NULL;
```

Optional. Recommended for forensics ("which spec was this peel
executed under?"). Nullable because we don't want to fail historical
peels if the schema evolves.

### 2.4 What is NOT being changed in schema

- **No re-add of `ephemeral_pubkey` to `recovery_blob_layers`.** The
  v1 wire format carries the ephemeral pubkey inside the encrypted
  layer bytes (see `RECOVERY_BLOB_FORMAT.md` §4.2 `ephPubkeyB64`),
  not in a separate column. Confirms V008's drop was correct.
- **No new tables.** The existing structure (one row per blob, one
  row per layer, one row per peel event) is sufficient.

## 3. Existing endpoint contract adjustments

### 3.1 `POST /recovery/blob` — narrow deltas vs deployed shape

Deployed `StoreBlobRequest` (per backend audit, post-rev2 of my
understanding):

```json
{
  "encryptedBlobB64": "<base64>",
  "rebuildReason": "<string, @NotBlank>",
  "layers": [
    {
      "layerOrder": 1,
      "partyId": "<uuid>",
      "partyType": "lawyer",
      "pubkeyId": "<server-internal ULID>",
      "keyFingerprint": "<64 hex>"
    },
    {
      "layerOrder": 2,
      "partyId": "<uuid>",
      "partyType": "nominee",
      "pubkeyId": "<server-internal ULID>",
      "keyFingerprint": "<64 hex>"
    }
  ]
}
```

v1 body (delta from deployed, additions and removals only):

```json
{
  "specVersion": "v1",
  "blobId": "<uuid v4>",
  "encryptedBlobB64": "<base64 string>",
  "rebuildReason": "initial",
  "layers": [
    {
      "layerOrder": 1,
      "partyId": "<uuid>",
      "partyType": "lawyer",
      "keyFingerprint": "<64 hex chars>"
    },
    {
      "layerOrder": 2,
      "partyId": "<uuid>",
      "partyType": "nominee",
      "keyFingerprint": "<64 hex chars>"
    }
  ]
}
```

Deltas:

- **ADD** top-level `specVersion: string` (NOT NULL, must equal
  `"v1"` initially; future spec versions widen the allowed set).
- **ADD** top-level `blobId: uuid` (client-generated UUID v4 so the
  UI can correlate before the response arrives — useful for optimistic
  UI). If backend prefers to generate server-side and ignore the
  client value, that's also fine but UI needs the response shape to
  return the assigned ID.
- **DROP** `layers[i].pubkeyId` — backend resolves the active pubkey via
  `SELECT pubkey_id, public_key_pem FROM party_public_keys WHERE party_id = ? AND party_type = ?::party_type_enum AND is_active = TRUE`
  (supported by `idx_pubkeys_active_party` partial unique index;
  exactly one row), then computes SHA-256 of the SPKI DER (decoded
  from the PEM) and asserts equality with the client-provided
  `keyFingerprint`. Mismatch → `RECOVERY_STALE_RECIPIENT_KEY` per §4.5.
- **KEEP** `rebuildReason` — required, non-blank. UI's allowed values:
  `"initial" | "nominee_added" | "nominee_removed" | "lawyer_changed" | "key_rotated" | "other"`.
  Backend currently `@NotBlank`; consider tightening to an enum check
  for these specific values — UI will only ever send one of them.
- **KEEP** layer field names exactly as deployed (`partyId`, `partyType`,
  `keyFingerprint`, `layerOrder`). Spec doc's "Metadata" naming used
  `recipientPartyId` etc., but backend wins on naming since the shape
  is deployed; UI will rename when constructing the request to match
  `BlobLayerRequest` exactly.

Schema mapping (post-v1):

- `specVersion` → `recovery_blobs.spec_version` AND copied to every
  `recovery_blob_layers.spec_version` for the inserted layers.
- `blobId` → `recovery_blobs.blob_id`.
- `encryptedBlobB64` → stored verbatim as today (opaque).
- `rebuildReason` → `blob_rebuild_log` row (existing forensic).
- `layers[]` → existing `recovery_blob_layers` insert path with the
  `pubkey_id` resolved server-side.

Response (rename from current `{blobId, layerCount, builtAt}` →
`{blobId, version, uploadedAt}`):

```json
{
  "blobId": "<uuid>",
  "version": <integer monotonic per creator>,
  "uploadedAt": "<ISO 8601>"
}
```

`version` semantics: per-creator monotonic counter — either count of
rows in `recovery_blobs` for the creator, or rank by `created_at`.
Backend's choice; UI just needs a monotonically-increasing integer.

### 3.2 `POST /recovery/session/{id}/peel` — field renames only

Current body: `{ intermediateCiphertextB64 }` (freeform bytes,
backend base64-decodes then SHA-256 hashes for audit; no length
constraint per `PeelHandler.java:150`). **No body change in v1.**

Current response shape (per backend audit):

```json
{
  "status": "IN_PROGRESS" | "COMPLETED" | "DISPUTED",
  "layersRemaining": <integer>,
  "nextPartyId": "<uuid> | null",
  "nextPartyType": "lawyer" | "nominee" | null
}
```

Backend has agreed to rename in `PeelHandler.PeelResponse` to match
spec:

```json
{
  "status": "IN_PROGRESS" | "COMPLETED" | "DISPUTED",
  "remainingLayers": <integer>,
  "nextRecipientPartyId": "<uuid> | null",
  "nextRecipientPartyType": "lawyer" | "nominee" | null
}
```

(Rename is trivial — single Java class. Backend's call to do it,
since the existing values aren't observed by any UI yet — A3 hasn't
implemented the peel screens.)

Audit log: backend will denormalize `recovery_peel_events.spec_version`
from the session's parent blob for forensic queries.

## 4. New validation rules at upload time

Backend should enforce these on `POST /recovery/blob`:

1. **Spec version known:**
   `specVersion IN ('v1')` initially; expand as future versions ship.
   On unknown: 400 with code `RECOVERY_UNSUPPORTED_SPEC_VERSION`.

2. **Recipient ordering (1-indexed):**
   `layers[0].partyType == 'lawyer'` (which is `layerOrder=1`).
   All other elements `partyType == 'nominee'`. On violation: 400
   with code `RECOVERY_INVALID_RECIPIENT_ORDER`.

3. **Layer count bounds:**
   `2 <= layers.length <= 7`. On violation: 400 with code
   `RECOVERY_LAYER_COUNT_OUT_OF_BOUNDS`. (UI policy: 1 lawyer +
   1..6 nominees. Backend enforces per agent confirmation Q5.)

4. **Recipient existence:** every `partyId` must resolve
   to a record owned by the creator (lawyer must be in this
   creator's lawyer set, nominees in this creator's nominee set).
   On violation: 400 with code `RECOVERY_UNKNOWN_RECIPIENT`.

5. **Pubkey-fingerprint match:** every `keyFingerprint`
   must equal SHA-256 of the SPKI DER bytes of the recipient's
   current active pubkey (resolved via
   `idx_pubkeys_active_party` partial unique index — exactly one
   row per (party_id, party_type) where `is_active = TRUE`).
   Prevents the client uploading a blob addressed to a stale key.
   On mismatch: 400 with code `RECOVERY_STALE_RECIPIENT_KEY` and
   details `{currentFingerprint: ..., providedFingerprint: ...}`.
   (This is also where the dropped `pubkeyId` field is implicitly
   resolved — see §3.1.)

6. **No duplicate recipients:** every `partyId` unique within
   the request. On violation: 400 with code
   `RECOVERY_DUPLICATE_RECIPIENT`.

7. **layerOrder dense & sequential (1-indexed):** elements 1..N
   with no gaps or repeats. On violation: 400 with code
   `RECOVERY_INVALID_LAYER_ORDERING`.

8. **`encryptedBlobB64` size cap:** suggest 32 KB hard cap (max
   1-lawyer + 6-nominees is ~5 KB; cap leaves headroom). Bigger →
   413 with code `RECOVERY_BLOB_TOO_LARGE`.

9. **`rebuildReason` enum check:** must be one of
   `"initial" | "nominee_added" | "nominee_removed" | "lawyer_changed" | "key_rotated" | "other"`.
   Current backend has it as `@NotBlank` only; tightening to enum
   makes auditing `blob_rebuild_log` queries cleaner. On violation:
   400 with code `VALIDATION_FAILED` and detail
   `{field: "rebuildReason", allowed: [...]}`.

10. **Rate limit:** 10 uploads per hour per creator. On violation:
    429 with existing code `RATE_LIMITED`. Backend implementation
    note: `OtpService.checkRateLimit` is auth-service only; recovery
    needs a separate `RecoveryBlobRateLimit` reading
    `recovery_blobs` count for last hour.

Error codes added to canonical `ErrorCode` enum:

- `RECOVERY_UNSUPPORTED_SPEC_VERSION`
- `RECOVERY_INVALID_RECIPIENT_ORDER`
- `RECOVERY_LAYER_COUNT_OUT_OF_BOUNDS`
- `RECOVERY_UNKNOWN_RECIPIENT`
- `RECOVERY_STALE_RECIPIENT_KEY`
- `RECOVERY_DUPLICATE_RECIPIENT`
- `RECOVERY_INVALID_LAYER_ORDERING`
- `RECOVERY_BLOB_TOO_LARGE`

(`VALIDATION_FAILED` and `RATE_LIMITED` already exist; reused.)

UI's `src/api/errors.ts` will be updated in lockstep when backend
publishes the canonical enum addition.

## 5. New endpoint — `GET /recovery/config`

Auth: none required (public config). Path kept inside the
recovery-service namespace per backend agent's preference (no need
for a `/config/*` top-level for a single endpoint).

Response:

```json
{
  "minWriteSpecVersion": "v1",
  "currentRecommendedSpecVersion": "v1",
  "supportedSpecVersionsForRead": ["v1"]
}
```

Semantics:

- `minWriteSpecVersion`: lowest spec the backend will accept for new
  `POST /recovery/blob` requests. UI compares its
  `CURRENT_WRITE_SPEC_VERSION` against this; if FE is behind, UI
  refuses to construct and prompts the user to update.
- `currentRecommendedSpecVersion`: backend's recommendation for new
  writes. UI may surface a "your locker is on an older spec, please
  rotate" nudge if `creator.lastRecoveryBlobSpec < currentRecommended`.
- `supportedSpecVersionsForRead`: which spec versions can still be
  peeled. Used by UI to warn before a peel session starts.

This is the **only** endpoint that influences UI crypto behavior,
and it does so by refusing — never by dictating. Compromised backend
serving `{minWriteSpecVersion: "v999"}` causes the UI to refuse new
writes; it cannot cause the UI to write under a malicious spec.

Caching: 5 minutes client-side is fine. No need for cache invalidation
since the value rarely changes.

## 6. Migration ordering

Simplified per rev 2 — no backwards-compat window needed because:

- The deployed `StoreBlobRequest` is already ~90 % v1 shape (`layers[]`,
  `rebuildReason` already there; only `specVersion`/`blobId` add, only
  `pubkeyId` drops).
- Zero existing recovery blobs in staging today.

Required deployment order:

1. **Backend** ships migration V011 (adds three `spec_version` columns
   per §2).
2. **Backend** ships endpoint changes atomically:
   - `POST /recovery/blob` accepts the v1 body shape (adds
     `specVersion` + `blobId`, drops `pubkeyId` from layer elements);
     `StoreBlobHandler` response renames (`layerCount`/`builtAt` →
     `version`/`uploadedAt`).
   - `POST /recovery/session/:id/peel` response renames (`layersRemaining`
     → `remainingLayers`, `nextPartyId` → `nextRecipientPartyId`,
     `nextPartyType` → `nextRecipientPartyType`).
   - `GET /recovery/config` returns
     `{minWriteSpecVersion: "v1", currentRecommendedSpecVersion: "v1", supportedSpecVersionsForRead: ["v1"]}`.
   - All 10 validation rules (§4) enforced from day 1.
3. **UI** ships v1 client code (post-final-ack), including:
   - `src/crypto/recoverySpec.ts` with `RECOVERY_SPEC_V1` constant.
   - `src/crypto/recoveryBlob.ts` with `constructRecoveryBlob` and
     `peelLayer` functions.
   - Updated `src/api/recovery.ts` consumer matching the new body
     shape (using backend's `partyId` / `partyType` / `keyFingerprint`
     / `layerOrder` field names within `layers[]`).
   - `src/api/config.ts` consumer for `GET /recovery/config` + a
     write-time gate that compares the local
     `CURRENT_WRITE_SPEC_VERSION` against `minWriteSpecVersion`.

Backend agent confirmed PR will include a docs mirror of both
specs into `deathtrap-backend/docs/`.

UI side has no separate data migration since there are zero existing
recovery blobs.

## 7. Acceptance criteria for backend dev agent

Backend should consider this work "done" when:

- [ ] Migration V011 applied to staging; `recovery_blobs.spec_version`
      and `recovery_blob_layers.spec_version` columns exist as
      `VARCHAR(16) NOT NULL DEFAULT 'v1'`;
      `recovery_peel_events.spec_version` exists as `VARCHAR(16) NULL`.
- [ ] `pubkeyId` removed from `BlobLayerRequest`; backend resolves
      via active-pubkey lookup and verifies fingerprint.
- [ ] `POST /recovery/blob` with the v1 body shape (top-level
      `specVersion` + `blobId`, no `pubkeyId` in layers) inserts one
      row in `recovery_blobs` and N rows in `recovery_blob_layers`,
      all with `spec_version = 'v1'`; `blob_rebuild_log` row written.
- [ ] All 10 validation rules (§4) reject with the documented error
      codes; rules 9 (`rebuildReason` enum) and 10 (rate limit) are
      new on the backend.
- [ ] 8 new error codes (§4) added to `ErrorCode.java` with matching
      `AppException` factory methods.
- [ ] `StoreBlobHandler` response renamed:
      `{blobId, layerCount, builtAt}` → `{blobId, version, uploadedAt}`.
- [ ] `PeelHandler.PeelResponse` renamed:
      `layersRemaining` → `remainingLayers`, `nextPartyId` →
      `nextRecipientPartyId`, `nextPartyType` → `nextRecipientPartyType`.
- [ ] `GET /recovery/config` returns the documented shape with
      static `v1` values.
- [ ] `RecoveryBlobRateLimit` enforces 10 uploads/hour/creator
      reading `recovery_blobs.created_at`.
- [ ] `StoreBlobHandlerTest` gains 8 cases (one per validation rule);
      `RecoveryConfigHandlerTest` new; integration test round-trips a
      sample upload (using `RECOVERY_BLOB_FORMAT.md` §11 shape, NOT
      the placeholder bytes).
- [ ] Both spec docs mirrored into `deathtrap-backend/docs/`,
      cross-linked.
- [ ] GitHub issue opened in `SynchroTwo/deathtrap-backend` with a
      checklist matching the items above.

## 8. UI side, post-ack

After backend ack lands, UI will:

1. Create `src/crypto/recoverySpec.ts` with `RECOVERY_SPEC_V1` and
   the `SUPPORTED_SPECS` map.
2. Implement `src/crypto/recoveryBlob.ts` with `constructRecoveryBlob`
   and `peelLayer` functions per `RECOVERY_BLOB_FORMAT.md` §5 and §7.
3. Generate `RECOVERY_TEST_VECTORS_V1.md` from the implementation
   (pinned random sources for reproducibility) — the markdown file the
   original request asked for, but now byte-reproducible from a
   reference impl that exists in the repo.
4. Wire `src/api/recovery.ts` to the new body shape; add
   `src/api/config.ts` consumer for `GET /config/recovery`.
5. Build UI surfaces in subsequent sprints (`FlowRecoveryDeath`,
   `FlowRecoveryForgot`) per Sprint A3.

## 9. Risks and mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| Backend's stricter validation breaks UI in production | Low | Feature flag in §6 step 3; enable after staging soak |
| Schema migration locks `recovery_blob` table | Low | `ADD COLUMN ... DEFAULT` is online in Postgres ≥11 (current is 15+); no exclusive lock |
| UI ships v1 code before backend ack | N/A | Manual checkpoint enforces this won't happen |
| Spec ambiguity discovered mid-implementation | Medium | Revisions land back in this doc; both sides re-ack before resuming |
| Real test vectors need primitives the runtime doesn't have | Low | All primitives already shipped in A0 (Web Crypto + hash-wasm) |
| Conflict with future regulatory signing requirement | Medium | v2 spec adds signing; v1 is forward-compatible via specVersion field |

## 10. Open questions — RESOLVED

All 10 questions answered in backend dev agent's
ACK-WITH-REVISIONS. Resolutions recorded below.

| Q | Resolution |
|---|---|
| Q1 | Reuse `recovery_blob_layers`. No new table. |
| Q2 | Schema (post-V008) already has `party_id`, `party_type`, `pubkey_id`, `key_fingerprint`, `layer_order`, `blob_id`, `layer_id`, `created_at`. Only missing `spec_version` per §2.2. |
| Q3 | One active pubkey per party at a time (partial unique index `idx_pubkeys_active_party`). Backend resolves by `(party_id, party_type, is_active=TRUE)` then verifies the client-provided `keyFingerprint` matches SHA-256 of SPKI DER. UI drops `pubkey_id` from the request (see §3.1). |
| Q4 | Yes — add `recovery_peel_events.spec_version VARCHAR(16) NULL`. Forensic value worth the column. |
| Q5 | 7 max (1 lawyer + 6 nominees). Backend enforces. |
| Q6 | 10/hour/creator on `POST /recovery/blob`. Separate `RecoveryBlobRateLimit` reading `recovery_blobs` count for last hour (not OtpService — that's auth-service only). Fail with `RATE_LIMITED` (existing code). |
| Q7 | `GET /recovery/config` — kept inside recovery-service namespace, no new top-level path. |
| Q8 | `intermediateCiphertextB64` is freeform bytes. `PeelHandler.java:150` base64-decodes then SHA-256-hashes; no length constraint. |
| Q9 | Yes — backend dev agent will mirror both docs into `deathtrap-backend/docs/` as part of the PR. |
| Q10 | GitHub issues in `SynchroTwo/deathtrap-backend`. Backend dev agent will open one with a checklist matching §7. |

## 11. Backend agent's escalations to user

Two items flagged for human ack before backend dev agent opens the
PR. Both confirmed in rev 2:

1. **Dropping `pubkeyId` from `BlobLayerRequest`.** Contract break
   for any UI code constructing the request. UI side verified:
   `src/api/recovery.ts` `PostRecoveryBlobReq` type contains no
   `pubkey_id` field (uses `partyId` + per-layer crypto fields only).
   No A2 / A1 / A0 code touches it. **Safe to drop unilaterally.**
2. **Layer ordering 1-indexed.** UI test vectors haven't been
   generated yet (gated on this checkpoint), so the change is
   free at this point. AAD bytes for the lawyer layer will be
   `...|1` (not `...|0`). Acknowledged and folded into BLOB_FORMAT.md
   throughout.

---

## How to reply

Backend dev agent: please respond with one of:

- **ACK** — rev 2 is implementable as drafted. UI proceeds to
  step 4 of the sprint plan; backend PR opens.
- **NEEDS FURTHER REVISIONS** — specific edits required. UI applies
  the edits, re-publishes both docs as rev 3, re-asks.
- **NEEDS DISCUSSION** — for any item to debate with the user before
  committing. UI pauses, user mediates.
- **BLOCK** — for any unresolvable constraint. UI redrafts.

Please cite the specific section number (`§4.5`, `§2.1`, etc.) for
any feedback so the diff is easy to apply.

End of backend changes doc (rev 2).
