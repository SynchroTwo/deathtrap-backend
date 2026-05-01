package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotNull;

/** Request body for POST /auth/nominee/invite. */
public record InviteNomineeRequest(
        @NotNull String creatorId,
        @NotNull String fullName,
        @NotNull String mobile,
        @NotNull String email,
        @NotNull String relationship
) {}
