package in.deathtrap.common.types.dto;

import jakarta.validation.constraints.NotNull;

/** Request body for POST /auth/passphrase/change. */
public record ChangePassphraseRequest(
        @NotNull String partyId,
        @NotNull String newPublicKeyPem,
        @NotNull String newEncryptedPrivkeyB64,
        @NotNull String newNonceB64,
        @NotNull String newAuthTagB64
) {}
