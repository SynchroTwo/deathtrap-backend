package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Request body for POST /auth/lawyer/register. */
public record RegisterLawyerRequest(
        @NotBlank @Size(max = 200) String fullName,
        @NotBlank String mobile,
        @NotBlank String email,
        @NotBlank @Size(max = 100) String barCouncil,
        @NotBlank @Size(max = 50) String enrollmentNo,
        @NotBlank String saltHex,
        @NotBlank String publicKeyPem,
        @NotBlank String keyFingerprint,
        @NotBlank String encryptedPrivkeyB64,
        @NotBlank String nonceB64,
        @NotBlank String authTagB64
) {}
