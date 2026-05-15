package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotNull;

/** Request body for POST /auth/session (login).
 *  OTP verification happens before this call via /auth/otp/verify-mobile
 *  with purpose=login. The verifiedToken is passed in the Authorization
 *  header; this body carries only identity + optional device telemetry. */
public record LoginRequest(
        @NotNull String mobile,
        String deviceId,
        String deviceFingerprint
) {}
