# Nominee Invite Token — Cross-Impl Test Vector V1

Purpose: pin one UI-generated invite token so the backend (`InviteTokenVerifierTest`) can
assert byte-level cross-platform agreement — the same role the recovery vectors play, but
**reversed ownership**: the UI owns signing, the backend owns verification.

## Why this can't pin signature bytes

ECDSA is non-deterministic (random `k` per signature), so a given (key, payload) yields a
*different* signature each run. The vector is therefore **verify-only**: it pins a key, a
payload, and one token the UI produced; the backend asserts that token *verifies* and that the
extracted payload matches. You cannot assert exact signature bytes.

## What the UI must provide

Paste these into the "Vector" section below. Generate once with the real
`signInviteToken` code path.

```
creatorPubkeyPem      : SPKI PEM (what GET /auth/creator/:id/pubkey returns)
creatorPrivkeyPkcs8B64 : PKCS#8 base64 of the same keypair (lets the backend also
                         round-trip sign+verify; omit if you'd rather not export it)
payload                : the exact InviteToken object (all 10 fields)
inviteTokenString      : the full base64url token your signInviteToken produced
```

## Backend assertions (wired once the vector lands)

1. `verify(inviteTokenString, creatorPubkeyPem)` → succeeds.
2. extracted payload fields == `payload`.
3. flip one byte of the token's payload region → `verify` throws `AUTH_INVITE_INVALID`.

## Status

**PENDING UI VECTOR.** Until it lands, `InviteTokenVerifierTest` proves correctness
self-consistently (it signs with `InviteTokenTestFactory` exactly as `inviteToken.ts` does,
then verifies + tampers). The self-consistent test guards the Java side; this vector will
guard cross-platform agreement.

## Vector

```
(paste here)
```
