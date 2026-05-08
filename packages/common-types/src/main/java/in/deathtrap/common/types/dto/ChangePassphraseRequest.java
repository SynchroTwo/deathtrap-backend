package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/** Request body for POST /auth/passphrase/change. partyId and partyType come from the session JWT. */
public record ChangePassphraseRequest(
        @NotBlank String newPublicKeyPem,
        @NotBlank String newKeyFingerprint,
        @NotBlank String newEncryptedPrivkeyB64,
        @NotBlank String newNonceB64,
        @NotBlank String newAuthTagB64,
        String hibpPrefix,
        String hibpSuffix,
        @NotNull Boolean hibpCheckResult
) {}
