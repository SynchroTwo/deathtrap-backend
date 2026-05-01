package in.deathtrap.common.types.domain;

import in.deathtrap.common.types.enums.PartyType;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;

/** Immutable snapshot of a client-encrypted private key blob. Server never decrypts this. */
public record EncryptedPrivkeyBlob(
        @NotNull String privkeyBlobId,
        @NotNull String partyId,
        @NotNull PartyType partyType,
        @NotNull String pubkeyId,
        @NotNull String ciphertextB64,
        @NotNull String nonceB64,
        @NotNull String authTagB64,
        int schemaVersion,
        int version,
        boolean isActive,
        @NotNull Instant activatedAt,
        Instant supersededAt,
        @NotNull Instant createdAt
) {}
