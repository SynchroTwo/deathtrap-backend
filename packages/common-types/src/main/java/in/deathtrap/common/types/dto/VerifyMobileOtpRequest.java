package in.deathtrap.common.types.dto;

import in.deathtrap.common.types.enums.OtpPurpose;
import jakarta.validation.constraints.NotNull;

/** Request body for POST /auth/otp/verify-mobile.
 *  For REGISTRATION purpose, email must be supplied so the handler can confirm
 *  the linked email OTP was also verified before issuing a verifiedToken. */
public record VerifyMobileOtpRequest(
        @NotNull String mobile,
        @NotNull String otp,
        @NotNull OtpPurpose purpose,
        String email
) {}
