package in.deathtrap.common.types.domain;

import in.deathtrap.common.types.enums.PartyType;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;

/** Immutable snapshot of an active or revoked session. */
public record UserSession(
        @NotNull String sessionId,
        @NotNull String partyId,
        @NotNull PartyType partyType,
        @NotNull String jwtJti,
        String deviceFingerprint,
        String ipAddress,
        String userAgent,
        @NotNull Instant expiresAt,
        Instant revokedAt,
        @NotNull Instant createdAt
) {}
