package in.deathtrap.common.types.domain;

import in.deathtrap.common.types.enums.KeyType;
import in.deathtrap.common.types.enums.PartyType;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;

/** Immutable snapshot of a party's active public key. */
public record PartyPublicKey(
        @NotNull String pubkeyId,
        @NotNull String partyId,
        @NotNull PartyType partyType,
        @NotNull KeyType keyType,
        @NotNull String publicKeyPem,
        @NotNull String keyFingerprint,
        int version,
        boolean isActive,
        @NotNull Instant activatedAt,
        Instant supersededAt,
        @NotNull Instant createdAt
) {}
