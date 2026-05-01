package in.deathtrap.common.types.dto;

import in.deathtrap.common.types.enums.OtpPurpose;
import jakarta.validation.constraints.NotNull;

/** Request body for POST /auth/otp/verify. */
public record VerifyOtpRequest(
        @NotNull String partyId,
        @NotNull OtpPurpose purpose,
        @NotNull String otp
) {}
