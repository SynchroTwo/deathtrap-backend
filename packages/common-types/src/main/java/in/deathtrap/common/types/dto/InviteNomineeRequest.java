package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Request body for POST /auth/nominee/invite. creatorId is extracted from the session JWT. */
public record InviteNomineeRequest(
        @NotBlank @Size(max = 200) String fullName,
        @NotBlank String mobile,
        @NotBlank String email,
        @NotBlank @Size(max = 100) String relationship
) {}
