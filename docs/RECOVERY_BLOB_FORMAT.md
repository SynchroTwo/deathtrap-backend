# Recovery Blob Format — Spec v1

> **Status:** DRAFT v1, **revision 2** — incorporating backend dev
> agent's ACK-WITH-REVISIONS feedback. Awaiting re-ack before client
> implementation begins.
> Nothing in this document is canonical until the backend dev agent has
> reviewed and ack'd the companion document
> `RECOVERY_SPEC_V1_BACKEND_CHANGES.md`. Until then, no test vectors
> are generated and no client code references "v1" outside this doc.

## Revision history

- **rev 2** (current): layer ordering switched to 1-indexed per
  backend's existing invariant (`@Min(1)` on `BlobLayerRequest`,
  `PeelHandler.expectedLayerOrder = maxPeeled + 1` starting from 0).
  AAD regex, peel math, illustrative payload, and construction loop
  updated accordingly. §10 upload contract gains the existing
  `rebuildReason` field (which the deployed `StoreBlobRequest`
  already requires). §12 open questions marked answered. Wire-shape
  diff vs the deployed backend `StoreBlobRequest` is now narrow —
  see `RECOVERY_SPEC_V1_BACKEND_CHANGES.md` §3.1.
- **rev 1** (superseded): initial draft.

---

## 1. Purpose

A recovery blob is the data structure that lets a creator's nominees +
lawyer collectively unlock the creator's locker when the creator is
incapacitated or deceased. It is constructed on the creator's device,
encrypted such that only the named recipients (in a fixed order) can
peel it, uploaded as opaque bytes to the backend, and re-assembled
piece by piece during a recovery session.

The blob is **layered (onion-shaped)**. The outermost layer is
addressed to the lawyer; each subsequent layer is addressed to a
specific nominee. Peeling proceeds in declared order: lawyer first,
then nominees one by one. The innermost layer reveals the creator's
`lockerKey` (32 bytes) — which is sufficient to decrypt the creator's
locker contents but **does not** reveal the creator's identity
(`privkey`) or their account (`masterKey`). Recovery is scoped to
"read the locker," not "become the creator."

## 2. Threat model

### In scope (defenses required)

1. **Backend compromise:** a fully compromised backend can drop /
   re-order / substitute blob bytes. Recipients must detect this and
   refuse to peel.
2. **Single-recipient compromise:** any one nominee or the lawyer
   colluding with the backend must not be able to bypass the rest of
   the recipient chain.
3. **Layer reordering:** a backend that swaps layer ordering or
   redirects a nominee's layer to the lawyer (or vice-versa) must
   cause a verifiable peel failure.
4. **Cross-blob substitution:** the layer from one creator's recovery
   blob must not be usable to bypass a layer in another creator's blob.
5. **Replay across spec versions:** a v1 layer must not be peelable as
   a v2 layer under a future spec.

### Out of scope (acknowledged limitations)

1. **All recipients colluding with the backend:** the recovery scheme
   IS the trust contract for the creator's data; if every named
   recipient agrees to peel, the locker opens. This is the design,
   not a bug.
2. **Recipient device compromise after peel:** once a recipient
   decrypts their layer, the next layer's ciphertext is in their
   memory. Compromised devices leak data the recipient was already
   authorized to see. Mitigation is operational (recipient device
   hygiene), not protocol.
3. **Backend choosing recipient list at write time:** the creator
   authenticates to the backend at upload via sessionJwt. A backend
   that ignores the creator's upload and stores a different one
   would be caught at peel time (recipient party IDs are bound by
   AAD), but only if peels are actually attempted.
4. **Identity recovery (privkey):** explicitly NOT recoverable by
   design. If the creator dies, their estate gets locker contents
   only — not the ability to sign messages as the creator.
5. **Forward secrecy after blob upload:** the encrypted blob sits at
   rest with the backend indefinitely. Anyone who later compromises
   ALL recipient privkeys can decrypt the blob. There is no
   post-compromise security at the blob level.

### Non-goals

1. Hiding the recipient identities from the backend. Backend learns
   the recipient list at upload time (required to orchestrate peels).
2. Hiding the layer count from the backend.
3. Anti-coercion / duress recovery. (May be added in a future spec.)

## 3. Cryptographic primitives

Single, homogeneous algorithm family. Same primitives the rest of the
app already uses; no new dependencies.

| Primitive | Algorithm | Source |
|---|---|---|
| Public-key keypairs | **ECDH P-256** (FIPS 186-4 / NIST SP 800-186) | All recipients (lawyer + nominees) use the same key type already stored as `key_type_enum='ecdh_p256'` |
| Key derivation | **HKDF-SHA-256** (RFC 5869) | Already in `src/crypto/hkdf.ts` |
| Symmetric encryption | **AES-256-GCM** (NIST SP 800-38D) | Already in `src/crypto/aes.ts` |
| Public-key wire format | **SPKI in PEM** for storage display; **raw uncompressed SEC1** (65 bytes, `0x04 ‖ X ‖ Y`) for ECDH exchange | Matches `src/crypto/ecdh.ts` post-A1 |
| Fingerprint | **SHA-256 hex of SPKI DER**, lowercase, 64 chars, no separators | Matches `src/crypto/fingerprint.ts` |

**No RSA, no AES-KW, no Ed25519.** A future spec version may introduce
others (and the version field allows it), but v1 is uniform.

### Why no creator signature in v1

Considered. Rejected because:

- The AAD (§6) binds every layer to `{specVersion, blobId, recipientPartyType, recipientPartyId, layerOrder}`. A backend that tampers with the recipient list or the ordering causes peel-time auth-tag failure, which is detectable.
- The creator authenticates the upload via `sessionJwt`. A backend that drops the upload and stores a different one is on record in audit logs.
- Adding a signature would require a separate signing keypair (NIST does not recommend reusing an ECDH key for ECDSA on the same curve), introducing a new key to manage, store, rotate.
- The marginal threat signing closes (backend swaps the entire recipient list AND knows the layer plaintexts) requires backend compromise of zero-knowledge anyway.

If a future regulatory or trust-anchor requirement demands signing, add to a v2 spec and bump.

## 4. Wire format

### 4.1 Top-level envelope (what the client uploads as a single opaque field)

```
recovery_envelope := {
  specVersion: "v1",
  blobId: <uuid>,
  saltHex: <64 hex chars = 32 random bytes>,
  layers: [ <outermost recovery_layer only> ]   // see §4.4 — russian-doll
}
```

`recovery_envelope` is JSON, then UTF-8 encoded, then base64-encoded.
The base64 string is what gets sent in `encryptedBlobB64`.

**Important:** Even though the envelope contains a `layers` array, the
backend never inspects it. Backend stores `encryptedBlobB64` as
opaque bytes. The `layers` metadata that the backend DOES persist
(for peel orchestration) is sent in a parallel structured field of
the upload request body — see §10.

### 4.2 Single layer

```
recovery_layer := {
  layerOrder: <integer, 1-indexed, ordered outermost-first>,
  recipientPartyType: "lawyer" | "nominee",
  recipientPartyId: <uuid of the recipient's party record>,
  recipientKeyFingerprint: <SHA-256 hex of recipient SPKI, 64 chars>,
  ephPubkeyB64: <base64 of 65-byte raw uncompressed SEC1 P-256 point>,
  nonceB64: <base64 of 12 random bytes>,
  ciphertextB64: <base64 of AES-GCM ciphertext>,
  authTagB64: <base64 of 16-byte AES-GCM tag>
}

// layerOrder is 1-indexed (lawyer = 1; nominees = 2..N) to match
// backend's @Min(1) constraint on BlobLayerRequest and PeelHandler's
// expectedLayerOrder = maxPeeled + 1 invariant. AAD byte-exactness
// requires consistency, not a particular starting point — backend's
// 1-indexed convention is preserved here.
```

### 4.3 Layer plaintext (what `ciphertextB64` decrypts to)

For all layers EXCEPT the innermost:

```
layer_plaintext := UTF-8 JSON of the NEXT layer (as a recovery_layer
object). Russian-doll style.
```

For the innermost layer:

```
innermost_plaintext := {
  payloadType: "lockerKey",
  lockerKeyHex: <64 hex chars = 32 raw bytes>,
  createdAt: <ISO 8601 timestamp>
}
```

Future spec versions may add other `payloadType` values (e.g.
`"lockerKey+saltHex"` for "let nominees re-derive masterKey"). v1
deliberately recovers only `lockerKey` to keep recovery scope minimal.

### 4.4 Why russian-doll instead of parallel layers

The russian-doll pattern means:

- Each peel produces ciphertext that becomes input to the next peel.
- Backend never needs to know layer structure — it just orchestrates
  "who peels next" via the parallel metadata and records SHA-256 of
  each peel's output for audit.
- Each recipient's layer also re-encrypts the inner state, so even
  inside a recipient's memory after their peel, the next layer's
  bytes are an opaque blob until the next recipient acts.
- The existing `PeelHandler` already implements this (audits via
  SHA-256 of `intermediateCiphertextB64`).

Parallel layers were considered and rejected: would require backend
to parse layer structure, which crosses the zero-knowledge line.

## 5. Construction algorithm

Input on the creator's device, AFTER unlock (so `lockerKey` is in
memory):

```
construct_recovery_blob(
  lockerKey:           Uint8Array(32),                      // creator's lockerKey
  blobId:              UUID,                                // newly generated
  recipients:          ordered list of
    { partyType: "lawyer" | "nominee",
      partyId: UUID,
      pubkeyPem: PEM string,                                // recipient's ECDH-P256 SPKI
      keyFingerprint: hex string }
) -> { encryptedBlobB64, layersMetadata }
```

Constraints on `recipients`:

- First element MUST have `partyType = "lawyer"`.
- All subsequent elements MUST have `partyType = "nominee"`.
- List length: 2..7 (1 lawyer + 1..6 nominees). Hard cap.

### 5.1 Steps

```
1. Generate envelope salt:
     salt := randomBytes(32)
     saltHex := hex(salt)

2. Build the innermost plaintext bytes:
     innermost_obj := {
       payloadType: "lockerKey",
       lockerKeyHex: hex(lockerKey),
       createdAt: <ISO 8601 now>
     }
     innermost_bytes := UTF-8(JSON.stringify(innermost_obj))

3. Initialize:
     current_plaintext := innermost_bytes
     N := recipients.length    // total layer count, 1-indexed cap

4. For i in reverse from N down to 1:
     // i is this layer's 1-indexed layerOrder.
     // Iterating reverse: innermost first (i = N), outermost last (i = 1).
     // recipients[i-1] is the recipient at layer i (recipients array is
     // 0-indexed in implementation but layerOrder is 1-indexed on the wire).
     recipient := recipients[i - 1]
     
     // Generate ephemeral keypair
     (eph_priv, eph_pub_raw_65b) := generateEcdhKeypair()
     
     // ECDH against recipient's pubkey
     recipient_pub_raw := SPKI-to-raw-65b(parsePEM(recipient.pubkeyPem))
     shared := ECDH(eph_priv, recipient_pub_raw)        // 32 bytes
     
     // HKDF-SHA-256 derive KEK
     info_bytes := UTF-8(
         "dt-recovery-layer-v1|" +
         <recipient.partyType> + "|" +
         <recipient.partyId>
     )
     KEK := HKDF-SHA-256(
         ikm = shared,
         salt = salt,                                     // envelope salt
         info = info_bytes,
         length = 32
     )
     
     // AAD (see §6 for byte-exact format)
     aad_bytes := build_aad(
         specVersion="v1",
         blobId=blobId,
         recipientPartyType=recipient.partyType,
         recipientPartyId=recipient.partyId,
         layerOrder=i                                     // 1-indexed
     )
     
     // Encrypt
     nonce := randomBytes(12)
     (ciphertext, authTag) := AES-256-GCM(
         key=KEK, nonce=nonce, plaintext=current_plaintext, aad=aad_bytes
     )
     
     // Build the layer object
     layer := {
         layerOrder: i,
         recipientPartyType: recipient.partyType,
         recipientPartyId: recipient.partyId,
         recipientKeyFingerprint: recipient.keyFingerprint,
         ephPubkeyB64: base64(eph_pub_raw_65b),
         nonceB64: base64(nonce),
         ciphertextB64: base64(ciphertext),
         authTagB64: base64(authTag)
     }
     
     // Re-wrap: next iteration's plaintext is THIS layer as JSON
     current_plaintext := UTF-8(JSON.stringify(layer))
     
     // Zeroize sensitive intermediates
     zeroize(eph_priv, shared, KEK, nonce)

5. After the loop, current_plaintext is the OUTERMOST layer (the
   lawyer's layer). Wrap it in the envelope:
     envelope := {
         specVersion: "v1",
         blobId: blobId,
         saltHex: saltHex,
         layers: [<the outermost layer, parsed back from current_plaintext>]
     }
   
   Wait — clarify: the russian-doll means each layer wraps the next.
   So the envelope's "layers" array contains ONLY the outermost layer
   object; all inner layers are encrypted inside it. Equivalently,
   "layers" is conceptually a single-element array containing the
   outermost.

6. Serialize envelope:
     envelope_json := JSON.stringify(envelope)
     envelope_bytes := UTF-8(envelope_json)
     encryptedBlobB64 := base64(envelope_bytes)

7. Build the PARALLEL metadata list (NOT secret — backend uses for
   peel orchestration):
     layersMetadata := [
       { layerOrder, recipientPartyType, recipientPartyId,
         recipientKeyFingerprint }
       for each recipient in original outermost-first order
     ]

8. Return { encryptedBlobB64, layersMetadata, blobId }.
```

### 5.2 Determinism / nondeterminism

The construction is **nondeterministic** — fresh randomness in salt,
ephemeral keypairs, and per-layer nonces. Two constructions over the
same inputs produce different outputs. Test vectors (when generated)
must therefore use pinned random sources.

## 6. AAD byte format

The AAD bytes used by AES-GCM at every layer are the UTF-8 encoding
of this string:

```
dt-recovery-v1|<blobId>|<recipientPartyType>|<recipientPartyId>|<layerOrder>
```

**Field constraints (enforced at construction time):**

- `blobId`: UUID v4 lowercase canonical form (8-4-4-4-12 hex chars
  with hyphens). Regex: `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`.
- `recipientPartyType`: literal string `lawyer` or `nominee`.
- `recipientPartyId`: UUID v4 lowercase canonical (same regex).
- `layerOrder`: **1-indexed** base-10 integer with no leading zeros.
  Regex: `[1-9]\d*`. Lawyer's layer is always `1`; first nominee `2`;
  etc. Matches backend's `@Min(1)` constraint on `BlobLayerRequest`.

**Separator:** ASCII `|` (0x7c). Single character. No padding, no
spaces.

**Why pipe-separated and not length-prefixed binary:** all field
values are constrained to `[0-9a-f-]` plus the two enum strings. No
escaping needed. Trivial to construct, trivial to compare byte-exact
in tests, human-readable in logs / hex dumps.

**No trailing newline. No BOM. No surrounding quotes.**

## 7. Reconstruction (peel) algorithm

### 7.1 Common to lawyer and nominees

Backend serves the same `encryptedBlobB64` to whoever is currently
authorized to peel (determined by `layersMetadata` ordering and
peel-events ledger). The peeling recipient:

```
peel_layer(
  encryptedInputB64:    string,          // either the envelope (first peel)
                                         // or the prior peeler's output
  recipientPrivkey:     CryptoKey,       // recipient's ECDH-P256 private
  expectedLayerOrder:   int,
  expectedRecipientPartyType: string,
  expectedRecipientPartyId:   UUID,
  blobId:               UUID              // from session metadata
) -> { nextEncryptedB64, isInnermost: bool, lockerKeyHex?: string }
```

Steps:

```
1. Parse the input:
     if expectedLayerOrder == 1 (first peel):
         envelope_bytes := base64-decode(encryptedInputB64)
         envelope := JSON.parse(UTF-8(envelope_bytes))
         assert envelope.specVersion == "v1"
         assert envelope.blobId == blobId
         layer_obj := envelope.layers[0]
         salt := hex-decode(envelope.saltHex)
     else:
         layer_obj := JSON.parse(UTF-8(base64-decode(encryptedInputB64)))
         // salt comes from session state (stored after the first peel)

2. Verify layer metadata matches what the session expects:
     assert layer_obj.layerOrder == expectedLayerOrder
     assert layer_obj.recipientPartyType == expectedRecipientPartyType
     assert layer_obj.recipientPartyId == expectedRecipientPartyId

3. Decode the cryptographic components:
     eph_pub_raw := base64-decode(layer_obj.ephPubkeyB64)
     nonce := base64-decode(layer_obj.nonceB64)
     ciphertext := base64-decode(layer_obj.ciphertextB64)
     authTag := base64-decode(layer_obj.authTagB64)
     assert eph_pub_raw.length == 65 && eph_pub_raw[0] == 0x04
     assert nonce.length == 12
     assert authTag.length == 16

4. ECDH against the ephemeral pubkey:
     shared := ECDH(recipientPrivkey, eph_pub_raw)       // 32 bytes

5. HKDF derive the same KEK the creator used:
     info_bytes := UTF-8(
         "dt-recovery-layer-v1|" +
         layer_obj.recipientPartyType + "|" +
         layer_obj.recipientPartyId
     )
     KEK := HKDF-SHA-256(ikm=shared, salt=salt, info=info_bytes, length=32)

6. Build AAD identical to construction:
     aad_bytes := build_aad("v1", blobId, layer_obj.recipientPartyType,
                            layer_obj.recipientPartyId, layer_obj.layerOrder)

7. Decrypt:
     plaintext := AES-256-GCM-decrypt(
         key=KEK, nonce=nonce, ciphertext=ciphertext, authTag=authTag,
         aad=aad_bytes
     )
     // AES-GCM auth-tag failure throws here — recipient sees
     // "RECOVERY_LAYER_TAMPERED" and refuses to forward.

8. Determine if innermost:
     try:
         maybe_inner := JSON.parse(UTF-8(plaintext))
         if maybe_inner.payloadType == "lockerKey":
             return {
                 isInnermost: true,
                 lockerKeyHex: maybe_inner.lockerKeyHex
             }
     catch:
         // Not innermost — plaintext is the next layer's JSON
         pass
     
     return {
         isInnermost: false,
         nextEncryptedB64: base64(plaintext)
     }

9. Zeroize KEK, shared.
```

### 7.2 Session orchestration (backend-side)

For each peel, the recipient submits `intermediateCiphertextB64` to
backend (the value of `nextEncryptedB64` for non-final peels, or a
fixed sentinel for the final peel). Backend records SHA-256 hash for
audit; serves the next ciphertext to the next authorized recipient.

The recipient ordering is determined by `layersMetadata`:

- First peel: lawyer (layerOrder = 1).
- Second peel: nominee with layerOrder = 2.
- ... etc.
- Final peel: nominee with layerOrder = N, whose decryption yields
  the `lockerKey`.

Where N is the total layer count (1 lawyer + (N-1) nominees).

The session is COMPLETED when the final peel returns
`isInnermost: true`. The final-peel recipient transmits the
`lockerKey` to the requesting party (the creator's estate, or the
creator themselves in the forgot-passphrase flow) via an
out-of-protocol channel — typically a one-time-use unwrap that
the UI orchestrates separately. (How the estate uses the
`lockerKey` to actually read the locker is the subject of a
separate spec; out of scope here.)

## 8. Versioning policy

### 8.1 Embedded version

Every recovery envelope carries `specVersion: "v1"`. Future versions
bump this string. Clients dispatch decrypt code based on the stored
value.

### 8.2 Forward compat

A v2 client MUST be able to peel v1 blobs. The reverse is not
required — a v1 client encountering a v2 blob throws
`UnsupportedRecoverySpecVersion`.

### 8.3 Write-side gating

The backend MAY advertise a `minWriteSpecVersion` via the config
endpoint described in `RECOVERY_SPEC_V1_BACKEND_CHANGES.md` §5. If a
client's `CURRENT_WRITE_SPEC_VERSION < minWriteSpecVersion`, the
client refuses to construct a new blob and prompts the user to
update the app. This is the **only** server-influence-on-crypto
permitted, and it is a refuse-to-act gate, not a recipe.

### 8.4 Deprecation path

When v1 is retired (no earlier than 2027, no earlier than 12 months
after v2 ships): backend rejects new v1 writes. Existing v1 blobs
remain readable indefinitely until an explicit migration pass
re-encrypts each user's blob under v2 (orchestrated by the UI,
because the creator is the only one who can re-encrypt).

## 9. Failure modes and error codes

| Code | Meaning | Recipient action |
|---|---|---|
| `RECOVERY_LAYER_TAMPERED` | AES-GCM auth tag failed | Refuse to forward. Surface "blob has been tampered with" to user. |
| `RECOVERY_LAYER_WRONG_RECIPIENT` | Layer's recipientPartyId doesn't match the peeling user | Refuse. Indicates backend served the wrong layer or session is misrouted. |
| `RECOVERY_LAYER_WRONG_ORDER` | layerOrder mismatch | Refuse. Indicates session out of sync. |
| `RECOVERY_UNSUPPORTED_SPEC_VERSION` | envelope.specVersion not in client's SUPPORTED_SPECS | Refuse. Prompt user to update app. |
| `RECOVERY_INVALID_INNERMOST_PAYLOAD` | Final peel's payloadType not in known set | Refuse. Indicates spec version skew. |
| `RECOVERY_LAYER_DECODE_ERROR` | Bytes don't parse as JSON / fields missing | Refuse. Indicates malformed blob. |

All failure modes are reported to backend via the dispute mechanism
(`POST /recovery/dispute`). Backend logs the dispute and notifies
the creator (if alive) and other recipients.

## 10. Backend / UI contract surface

The construction in §5 produces:

- `encryptedBlobB64`: opaque single field, ~few KB.
- `layersMetadata`: parallel array, **non-secret**, used by backend
  for peel orchestration and audit. Each entry has only the four
  fields needed for routing:
  `{ layerOrder, recipientPartyType, recipientPartyId, recipientKeyFingerprint }`.

Upload request body to `POST /recovery/blob`:

```json
{
  "specVersion": "v1",
  "blobId": "<uuid>",
  "encryptedBlobB64": "...",
  "rebuildReason": "initial",
  "layersMetadata": [
    {
      "layerOrder": 1,
      "recipientPartyType": "lawyer",
      "recipientPartyId": "<uuid>",
      "recipientKeyFingerprint": "<64 hex>"
    },
    {
      "layerOrder": 2,
      "recipientPartyType": "nominee",
      "recipientPartyId": "<uuid>",
      "recipientKeyFingerprint": "<64 hex>"
    }
  ]
}
```

`rebuildReason`: required, non-blank. One of `"initial"`,
`"nominee_added"`, `"nominee_removed"`, `"lawyer_changed"`,
`"key_rotated"`, `"other"`. Logged to `blob_rebuild_log` on the
backend for forensics. This field was already required by the
deployed `StoreBlobRequest` — preserved in v1 to avoid breakage.

Notable: the deployed backend already accepts `layers[]` with
`partyId`, `partyType`, `keyFingerprint`, `layerOrder` per element.
Spec v1 adds `specVersion` to the top-level body and drops `pubkeyId`
from each layer element (backend resolves the active pubkey by
`(partyId, partyType, is_active=TRUE)` then verifies fingerprint).

Upload response: `{ blobId, version, uploadedAt }` (version is
monotonic per creator — current blob count or `created_at` rank;
backend implementation detail).

Detailed schema/migration/endpoint asks are in
`RECOVERY_SPEC_V1_BACKEND_CHANGES.md`.

## 11. Illustrative wire payload (NOT a test vector)

The bytes below are **NOT** to be used as a test vector. They are
illustrative — to show the shape and approximate sizes of a real
upload. Real test vectors will be generated only after backend
sign-off, and will be byte-reproducible from a pinned reference
implementation.

```
POST /recovery/blob
Content-Type: application/json
Authorization: Bearer <creator session jwt>

{
  "specVersion": "v1",
  "blobId": "1e2c3a44-9b10-4d51-bfe2-77c8a2419f01",
  "encryptedBlobB64": "<....ILLUSTRATIVE — not a real ciphertext....>",
  "rebuildReason": "initial",
  "layersMetadata": [
    {
      "layerOrder": 1,
      "recipientPartyType": "lawyer",
      "recipientPartyId": "8f429100-ec91-4a9d-bc9b-cffd940142c8",
      "recipientKeyFingerprint": "47fb7de221a039094abcc78ecd2c6aed7ae482dcd01d9ed4c43ca0a37a3b073c"
    },
    {
      "layerOrder": 2,
      "recipientPartyType": "nominee",
      "recipientPartyId": "c2d0a4f1-1234-4ef2-9876-aaaaaaaaaaaa",
      "recipientKeyFingerprint": "deadbeef000102030405060708090a0b0c0d0e0f101112131415161718191a1b"
    },
    {
      "layerOrder": 3,
      "recipientPartyType": "nominee",
      "recipientPartyId": "c2d0a4f1-5678-4ef2-9876-bbbbbbbbbbbb",
      "recipientKeyFingerprint": "cafebabe000102030405060708090a0b0c0d0e0f101112131415161718191a1b"
    }
  ]
}
```

The `encryptedBlobB64` decoded shows the envelope's outermost form
(single layer object inside `layers` array — the inner nominee layers
are nested inside the lawyer layer's ciphertextB64 once decrypted).
The `ciphertextB64` body is replaced with the literal placeholder
`<....ILLUSTRATIVE....>` to make clear this is not a real ciphertext.

Approximate sizes for a 1-lawyer + 2-nominee blob:
- Envelope JSON: ~250 bytes
- Each layer JSON (encrypted): ~250 bytes
- Each ciphertext expansion: plaintext + 16-byte tag
- Total `encryptedBlobB64`: ~1.5 KB (base64 includes ~33% overhead)

For the max case (1 lawyer + 6 nominees), expect ~5 KB.

## 12. Open questions for backend agent — RESOLVED

All 5 spec-side questions were answered in backend dev agent's
ACK-WITH-REVISIONS response. Recorded below for spec-doc
completeness; full backend response is summarized in
`RECOVERY_SPEC_V1_BACKEND_CHANGES.md` §10.

1. **Reuse `recovery_blob_layers`** — confirmed. No new table.
2. **Peel endpoint** — no spec-v1-specific changes needed; russian-doll
   opaque-bytes pattern works as-is. `intermediateCiphertextB64` is
   freeform (`PeelHandler.java:150` base64-decodes then SHA-256
   hashes; no length constraint).
3. **`spec_version` in audit log** — yes, add `recovery_peel_events.spec_version VARCHAR(16) NULL`
   for forensics.
4. **Recipient-ordering invariant** — backend enforces (lawyer at
   `layerOrder=1`, nominees `2..N`). UI also enforces client-side as
   defense in depth.
5. **Layer count cap** — 7 confirmed (1 lawyer + 6 nominees).
   Backend enforces.

End of spec v1 (revision 2).
