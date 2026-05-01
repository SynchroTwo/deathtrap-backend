package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotNull;

/** Request body for POST /auth/lawyer/register. */
public record RegisterLawyerRequest(
        @NotNull String fullName,
        @NotNull String mobile,
        @NotNull String email,
        @NotNull String barCouncil,
        @NotNull String enrollmentNo,
        @NotNull String publicKeyPem,
        @NotNull String encryptedPrivkeyB64,
        @NotNull String nonceB64,
        @NotNull String authTagB64,
        @NotNull String saltHex
) {}
