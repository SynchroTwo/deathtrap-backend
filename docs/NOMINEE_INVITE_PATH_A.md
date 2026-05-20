# Nominee Invite — Path A (client-signed ECDSA invite tokens)

Sprint A3. The creator's browser signs a self-contained invite token with its ECDSA-P256
key; the backend verifies that signature against the creator's stored pubkey on accept. The
backend never issues or stores an invite secret. All endpoints live under the already-routed
`/auth` prefix (no API Gateway / CDK change).

Backend: `InviteTokenVerifier`, `NomineeManagementHandler`, `NomineeAcceptHandler`,
`CreatorPubkeyHandler`. Migration: `V012__nominees_path_a.sql`.

---

## 1. Invite-token signature contract

Token string (single base64url blob, no padding):

```
canonical  = canonicalJson(payload)            # sorted keys, no whitespace, UTF-8
inner      = SHA-256(canonical)
signature  = base64( ECDSA_P256( SHA-256(inner) ) )   # WebCrypto ECDSA{hash:"SHA-256"} double-hashes;
                                                       # raw r||s P1363, 64 bytes, base64-standard
token      = base64url( utf8( canonicalJson({payload, signature}) ) )
```

`payload` (InviteToken) fields:

| field          | type            | notes                                  |
|----------------|-----------------|----------------------------------------|
| schemaVersion  | number (== 1)   |                                        |
| purpose        | "creator-invite-nominee" |                               |
| creatorId      | string          | resolves which creator pubkey verifies |
| creatorName    | string          | display only                           |
| nomineeId      | string          | server-issued by POST /auth/nominees   |
| fullName       | string          |                                        |
| email          | string \| null  |                                        |
| mobile         | string \| null  |                                        |
| expiresAt      | string (ISO-8601)| rejected with 410 if in the past      |
| nonce          | string          | replay-uniqueness                      |

**Verification is byte-exact, not re-canonicalized.** Because the outer object sorts
`payload` before `signature`, the payload object embedded in the decoded token is
byte-identical to `canonicalJson(payload)` — the exact bytes that were signed. The backend
extracts that substring verbatim (brace-balanced, string-aware) and verifies over it. This
means cross-platform canonical-JSON differences (null handling, number formatting, escaping)
**cannot** break verification: the backend checks the literal bytes the UI signed.

JCE algorithm: `Signature.getInstance("SHA256withECDSAinP1363Format")` (SunEC, accepts raw
64-byte r||s). Pubkey loaded from SPKI PEM via `KeyFactory("EC")` + `X509EncodedKeySpec`.

Cross-impl test vector: see `NOMINEE_INVITE_TEST_VECTOR_V1.md` (UI-generated, backend-verified).

---

## 2. Endpoints (all under `/auth`)

| Method & path | Auth | Request | Success |
|---|---|---|---|
| `POST /auth/nominees` | creator JWT | `{fullName, email?, mobile?, expiresAt?}` | `201 {nominee: NomineeView}` |
| `GET /auth/nominees` | creator JWT | — | `200 {nominees: NomineeView[]}` |
| `PATCH /auth/nominees/:id` | creator JWT | `{fullName?, email?, mobile?}` (non-null applied) | `200 NomineeView` |
| `DELETE /auth/nominees/:id` | creator JWT | — | `204` (soft delete, status→removed) |
| `POST /auth/nominees/:id/resend` | creator JWT | — | `200 {nomineeId, lastResendAt}` |
| `GET /auth/nominees/:id/pubkey` | creator JWT | — | `200 {pubkeyPem, fingerprint}` (404 until accept) |
| `GET /auth/creator/:id/pubkey` | **public** | — | `200 {pubkeyPem, fingerprint}` |
| `POST /auth/nominee/accept` | **public** (token authenticates) | see §3 | `201` see §3 |

> Note: handlers return `NomineeView` directly as `data`; the table's `{nominee}` / `{nominees}`
> wrapper refers to the UI's `api/nominees.ts` expectation. The envelope is always
> `ApiResponse<T>` = `{success, data, error, requestId}`, so the UI reads `data` for the view(s).

`NomineeView` = `{nomineeId, creatorId, fullName, email|null, mobile|null, status,
pubkeyPem|null, pubkeyFingerprint|null, invitedAt, registeredAt|null, removedAt|null}`.

**Creator pubkey format:** returned as SPKI **PEM** + lowercase-hex SHA-256(SPKI DER)
fingerprint. The UI converts PEM → raw SEC1 for its WebCrypto verify. (Ask if a
`pubkeyRawB64` field is preferred to skip the conversion — trivial to add.)

---

## 3. Accept — body, salt, session reconciliation

Request (`POST /auth/nominee/accept`):

```
{ inviteToken, pubkeyPem, encryptedPrivkeyB64,
  encryptedPrivkeyNonceB64, encryptedPrivkeyTagB64, saltB64 }
```

- `saltB64` (base64) is decoded → hex server-side and stored in `party_salts.salt_hex`
  (creator-register uses `saltHex`; no UI change required for nominee accept).
- `pubkeyPem` stored in `party_public_keys.public_key_pem`; fingerprint computed server-side.
- `encryptedPrivkeyB64/NonceB64/TagB64` → `encrypted_privkey_blobs.ciphertext_b64/nonce_b64/auth_tag_b64`.

Response (extended beyond the zip's bare `sessionToken`, to match
`LoginResponse`/`RegisterCreatorResponse` so `AuthContext.setSession` consumes it directly):

```
201 { nomineeId, creatorId, partyType: "nominee",
      sessionJwt, refreshToken, expiresAt }
```

`expiresAt` is the access-token (15 min) expiry, ISO-8601, for refresh scheduling.

**Lifecycle / status:** accept sets nominee status to **`active`** (not `registered`).
Recovery-blob eligibility (`StoreBlobHandler`) and locker nominee assignment both require
`status='active'`, so path A collapses the accepted state into `active`. UI status set is
therefore `invited | active | removed`; the `registered` enum value is reserved/unused.
`registeredAt` is still populated with the accept timestamp.

**Replay / double-accept:** the pre-check rejects any nominee not in `invited` status
(`NOMINEE_ALREADY_REGISTERED`); the conditional `UPDATE ... WHERE status='invited'` closes the
race if two accepts arrive concurrently. `invite_payload_hash` records SHA-256 of the accepted
payload for audit.

---

## 4. Error codes (envelope `error.code`)

| code | HTTP | when |
|---|---|---|
| `AUTH_INVITE_INVALID` | 400 | malformed token / wrong purpose / wrong schemaVersion / **signature verify fail** / unknown creator pubkey |
| `AUTH_INVITE_EXPIRED` | 410 | `payload.expiresAt` is in the past |
| `NOMINEE_NOT_FOUND` | 404 | nominee id (path or token) not owned by this creator |
| `NOMINEE_ALREADY_REGISTERED` | 409 | nominee already accepted (status ≠ invited) |
| `VALIDATION_FAILED` | 400 | bad pubkey PEM / bad saltB64 / bad expiresAt |
| `AUTH_UNAUTHORIZED` | 401 | missing/!Bearer on a creator-authed route |
| `AUTH_FORBIDDEN` | 403 | non-creator JWT on a creator-authed route |

---

## 5. Go-live

- **CORS:** new endpoints inherit the existing `/auth/*` allowlist (B8) — no CORS change.
- **Migration:** apply `V012` to staging RDS before deploy.
- **Deploy:** redeploy auth-service Lambda; flip UI `VITE_USE_MSW=false` once confirmed.

---

## 6. Deferred gaps (A4/A6) — recovery peel chain

Not blockers for A3 or A4 (A4 uses MSW mocks), tracked for A6:

- **Peel-chain ciphertext is not served.** `PeelHandler` stores only SHA-256 of
  `intermediateCiphertextB64`, and `GetSessionStatusHandler` serves no ciphertext — so peeler
  N+1 cannot fetch peeler N's output. A6 must store + serve `currentEncryptedB64`.
- **`PeelResponse.sessionStatus`** field name + lowercase status values diverge from the
  uppercase enum convention; reconcile to `status` + uppercase in A6.
- **`GET /recovery/blob/current`** metadata endpoint missing.
- **Dispute contract** for the peel flow undefined.
