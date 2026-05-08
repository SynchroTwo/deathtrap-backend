package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotBlank;

/** Request body for POST /auth/nominee/register. */
public record RegisterNomineeRequest(
        @NotBlank String inviteToken,
        @NotBlank String saltHex,
        @NotBlank String publicKeyPem,
        @NotBlank String keyFingerprint,
        @NotBlank String encryptedPrivkeyB64,
        @NotBlank String nonceB64,
        @NotBlank String authTagB64,
        String deviceId,
        String deviceFingerprint
) {}
