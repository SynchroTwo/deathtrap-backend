package in.deathtrap.common.types.domain;

import in.deathtrap.common.types.enums.LawyerStatus;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;

/** Immutable snapshot of a lawyer fetched from the database. */
public record Lawyer(
        @NotNull String lawyerId,
        @NotNull String fullName,
        @NotNull String mobile,
        @NotNull String email,
        @NotNull String barCouncil,
        @NotNull String enrollmentNo,
        boolean barVerified,
        Instant barVerifiedAt,
        @NotNull LawyerStatus status,
        boolean kycAdminApproved,
        Instant kycApprovedAt,
        @NotNull Instant createdAt,
        @NotNull Instant updatedAt
) {}
