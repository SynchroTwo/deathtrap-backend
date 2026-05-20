package in.deathtrap.common.types.dto;

/** Response body for POST /auth/nominee/accept.
 *  Shape aligned with LoginResponse / RegisterCreatorResponse so the UI's
 *  AuthContext.setSession can consume it directly. The nominee is logged in
 *  immediately on a successful accept. expiresAt is the access-token (15 min)
 *  expiry for refresh scheduling. */
public record AcceptInviteResponse(
        String nomineeId,
        String creatorId,
        String partyType,
        String sessionJwt,
        String refreshToken,
        String expiresAt
) {}
