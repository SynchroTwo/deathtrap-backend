package in.deathtrap.common.types.dto;

/** Response body for POST /auth/session/refresh.
 *  Returns a freshly minted access token (sessionJwt) bound to the same
 *  session as the supplied refresh token. The refresh token is re-issued
 *  with the same JTI; clients may overwrite their stored refresh token
 *  with this value or keep the existing one — both remain valid until
 *  natural expiry or session revocation. */
public record RefreshSessionResponse(
        String sessionJwt,
        String refreshToken,
        String expiresAt
) {}
