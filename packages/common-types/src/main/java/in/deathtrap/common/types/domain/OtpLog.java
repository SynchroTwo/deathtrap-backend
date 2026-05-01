package in.deathtrap.common.types.domain;

import in.deathtrap.common.types.enums.OtpChannel;
import in.deathtrap.common.types.enums.OtpPurpose;
import in.deathtrap.common.types.enums.PartyType;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;

/** Immutable snapshot of a one-time password log entry. */
public record OtpLog(
        @NotNull String otpId,
        @NotNull String partyId,
        @NotNull PartyType partyType,
        @NotNull OtpChannel channel,
        @NotNull OtpPurpose purpose,
        @NotNull String otpHash,
        int attempts,
        boolean verified,
        Instant lockedUntil,
        @NotNull Instant expiresAt,
        @NotNull Instant createdAt
) {}
