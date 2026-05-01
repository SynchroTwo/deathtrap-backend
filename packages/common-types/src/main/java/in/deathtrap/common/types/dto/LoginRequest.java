package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotNull;

/** Request body for POST /auth/session (login). */
public record LoginRequest(
        @NotNull String mobile,
        @NotNull String mobileOtp,
        @NotNull String emailOtp,
        String deviceId,
        String deviceFingerprint
) {}
