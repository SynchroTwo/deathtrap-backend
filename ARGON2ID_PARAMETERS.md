# Argon2id Parameter Guidance — DeathTrap Mobile Clients
Sprint 9 | 2026-05-08

## Recommended Parameters

| Parameter    | Value      | Notes                                      |
|-------------|------------|--------------------------------------------|
| Algorithm   | Argon2id    | Hybrid of Argon2i (side-channel) + Argon2d (GPU) |
| Memory cost | 65 536 KB  | 64 MB — comfortable on mid-range Android/iOS  |
| Iterations  | 3           | Time cost; increase to 4–5 on high-end devices |
| Parallelism | 2           | Matches 2 physical cores on low-end phones    |
| Output      | 32 bytes    | 256-bit master key, fed into HKDF            |
| Salt        | 16 bytes    | Randomly generated per-user, stored server-side in `party_salts` |

## Why These Values

### Memory: 64 MB
The [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) and the Argon2 RFC (7686) both recommend at least 64 MB for interactive logins. Lower memory (e.g., 19 MB as in many defaults) reduces GPU-attack resistance proportionally. 64 MB is the practical maximum that low-end Android devices (≥ 2 GB RAM) can sustain without an OOM kill during the key-derivation step.

### Iterations: 3
With 64 MB memory, 3 passes delivers ≈ 700 ms on a mid-range 2022 phone (Snapdragon 695). This is below the 1-second UX threshold for a login flow. Increase to 4 on flagships without noticeably affecting UX.

### Parallelism: 2
Argon2id's parallelism degree should not exceed the number of physical cores available to the derivation thread. Two is safe for all current mobile SoCs. Setting it higher than available cores does not increase security and can cause scheduling jitter.

### Output: 32 bytes
The 256-bit derived key is used as the IKM (input key material) for HKDF-SHA256, which then stretches it into:
- A 32-byte AES-256-GCM key for encrypting the user's private key before upload.
- (Optionally) a 32-byte MAC key for client-side integrity checks.

## Integration with Server-Side Salt Storage

```
Client                           Server
------                           ------
1. POST /auth/otp/send            → inserts party_id row
2. POST /auth/otp/verify          → returns verified_token
3. Client generates random salt (16 bytes)
4. Client runs Argon2id(passphrase, salt, m=65536, t=3, p=2) → masterKey
5. Client encrypts privkey: AES-256-GCM(privkey, masterKey)
6. POST /auth/register            → sends { encryptedPrivkeyB64, pubkeyB64, saltB64 }
                                  ← server stores salt in party_salts,
                                     stores encryptedPrivkeyB64 in encrypted_privkey_blobs
```

On login the client must:
1. Retrieve the salt from the server (`GET /auth/salt` or embedded in OTP-verify response).
2. Re-derive `masterKey` from the user's passphrase + stored salt.
3. Decrypt the private key locally.

The server **never** sees the passphrase or the derived master key.

## Benchmark Targets (reference hardware)

| Device class          | Expected wall time |
|----------------------|--------------------|
| Low-end (Cortex-A55) | ≤ 1200 ms          |
| Mid-range (Snapdragon 695 / A15) | ≤ 700 ms |
| Flagship (Snapdragon 8 Gen 3 / A17) | ≤ 300 ms |

If benchmarks on a target device exceed 1500 ms, reduce memory to 32 768 KB (32 MB) as a fallback and document the change.

## Library Recommendations

| Platform | Library                   | Notes                              |
|----------|---------------------------|------------------------------------|
| Android  | `com.lambdapioneer.argon2kt:argon2kt` or `de.mkammerer:argon2-jvm-nolibs` | Bundles native `.so`; no Play Services dependency |
| iOS      | `swift-argon2` (Apple SPM) or `CryptoKit`-based wrapper | CryptoKit does not expose Argon2id natively; use a thin ObjC bridge |
| React Native | `react-native-argon2` | Calls native Argon2 implementation on each platform |

## Parameter Versioning

If parameters must be changed in a future release (e.g., to increase memory), the `party_salts` table should store a `kdf_version` column so that the client knows which parameters to use when re-deriving on an older account. Current version: **v1** (parameters above).

## References

- RFC 7693 — The Argon2 Memory-Hard Function
- OWASP Password Storage Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- Signal Protocol Key Derivation — inspiration for HKDF chaining pattern
