package in.deathtrap.common.types.dto;

import in.deathtrap.common.types.enums.OtpPurpose;
import jakarta.validation.constraints.NotNull;

/** Request body for POST /auth/otp/verify-email.
 *  Only REGISTRATION purpose supports email OTP. mobile must be supplied so the
 *  handler can confirm the linked mobile OTP was also verified before issuing
 *  a verifiedToken. */
public record VerifyEmailOtpRequest(
        @NotNull String email,
        @NotNull String otp,
        @NotNull OtpPurpose purpose,
        @NotNull String mobile
) {}
