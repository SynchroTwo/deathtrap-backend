package in.deathtrap.common.types.dto;

import in.deathtrap.common.types.enums.PartyType;

/** Represents the claims extracted from a validated JWT. */
public record JwtPayload(
        String sub,
        PartyType partyType,
        String jti,
        long iat,
        long exp
) {}
