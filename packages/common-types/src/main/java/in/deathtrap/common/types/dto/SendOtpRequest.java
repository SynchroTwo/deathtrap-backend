package in.deathtrap.common.types.dto;

import in.deathtrap.common.types.enums.OtpPurpose;
import jakarta.validation.constraints.NotNull;

/** Request body for POST /auth/otp/send. */
public record SendOtpRequest(
        String mobile,
        String email,
        @NotNull OtpPurpose purpose
) {}
