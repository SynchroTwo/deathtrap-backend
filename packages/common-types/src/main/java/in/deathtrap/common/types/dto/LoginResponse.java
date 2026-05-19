package in.deathtrap.common.types.dto;

/** Response body for POST /auth/session (login).
 *  Returns session tokens + the encrypted-privkey material the client needs
 *  to derive its in-memory masterKey/lockerKey via runLoginCryptoPipeline.
 *  Server never sees or stores plaintext — these fields are opaque ciphertext. */
public record LoginResponse(
        String userId,
        String partyType,
        String sessionJwt,
        String refreshToken,
        String expiresAt,
        String saltHex,
        String encryptedPrivkeyB64,
        String encryptedPrivkeyNonceB64,
        String encryptedPrivkeyTagB64
) {}
