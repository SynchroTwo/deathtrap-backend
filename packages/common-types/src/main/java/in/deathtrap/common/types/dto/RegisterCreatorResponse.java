package in.deathtrap.common.types.dto;

/** Response body for POST /auth/register.
 *  Issues session + refresh tokens immediately on register so the client can
 *  proceed to /locker/init and the dashboard without a separate login round-trip.
 *  lockerInitRequired is always true on first register; remains true until the
 *  client successfully calls POST /locker/init. */
public record RegisterCreatorResponse(
        String userId,
        String sessionJwt,
        String refreshToken,
        String expiresAt,
        boolean lockerInitRequired
) {}
