package in.deathtrap.common.types.domain;

import in.deathtrap.common.types.enums.PartyType;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;

/** Immutable snapshot of a party's KDF salt (64-char hex). */
public record PartySalt(
        @NotNull String saltId,
        @NotNull String partyId,
        @NotNull PartyType partyType,
        @NotNull String saltHex,
        int schemaVersion,
        @NotNull Instant createdAt
) {}
