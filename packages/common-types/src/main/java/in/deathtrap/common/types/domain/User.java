package in.deathtrap.common.types.domain;

import in.deathtrap.common.types.enums.KycStatus;
import in.deathtrap.common.types.enums.UserStatus;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;
import java.time.LocalDate;

/** Immutable snapshot of a creator user fetched from the database. */
public record User(
        @NotNull String userId,
        @NotNull String fullName,
        @NotNull LocalDate dateOfBirth,
        @NotNull String mobile,
        @NotNull String email,
        String address,
        String panRef,
        String aadhaarRef,
        @NotNull KycStatus kycStatus,
        @NotNull UserStatus status,
        Instant riskAcceptedAt,
        Integer zeroNomineeRiskVersion,
        int lockerCompletenessPct,
        Instant lastReviewedAt,
        int inactivityTriggerMonths,
        @NotNull Instant createdAt,
        @NotNull Instant updatedAt,
        Instant deletedAt
) {}
