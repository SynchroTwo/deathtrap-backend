package in.deathtrap.common.types.dto;

import in.deathtrap.common.types.enums.OtpPurpose;
import jakarta.validation.constraints.NotNull;

/** Request body for POST /auth/session. */
public record LoginRequest(
        @NotNull String mobile,
        @NotNull OtpPurpose purpose,
        @NotNull String verifiedOtpToken
) {}
