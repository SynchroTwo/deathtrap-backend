package in.deathtrap.common.types.domain;

import in.deathtrap.common.types.enums.NomineeStatus;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;

/** Immutable snapshot of a nominee fetched from the database. */
public record Nominee(
        @NotNull String nomineeId,
        @NotNull String creatorId,
        @NotNull String fullName,
        @NotNull String mobile,
        @NotNull String email,
        @NotNull String relationship,
        int registrationOrder,
        String inviteTokenHash,
        Instant inviteExpiresAt,
        @NotNull NomineeStatus status,
        boolean fingerprintVerified,
        Instant fingerprintVerifiedAt,
        @NotNull Instant createdAt,
        @NotNull Instant updatedAt
) {}
