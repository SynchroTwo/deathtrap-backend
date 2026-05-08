package in.deathtrap.common.types.dto;

import java.time.Instant;

/** Response body for POST /auth/nominee/register. */
public record NomineeRegisterResponse(
        String nomineeId,
        String accessToken,
        String sessionId,
        Instant expiresAt
) {}
