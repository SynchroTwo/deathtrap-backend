package in.deathtrap.common.types.domain;

import jakarta.validation.constraints.NotNull;
import java.time.Instant;

/** Immutable snapshot of a locker metadata record. */
public record LockerMeta(
        @NotNull String lockerId,
        @NotNull String userId,
        int completenessPct,
        int onlinePct,
        int offlinePct,
        boolean blobBuilt,
        Instant lastSavedAt,
        @NotNull Instant createdAt,
        @NotNull Instant updatedAt
) {}
