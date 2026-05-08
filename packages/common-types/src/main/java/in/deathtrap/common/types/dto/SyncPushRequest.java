package in.deathtrap.common.types.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

/** Request body for the WatermelonDB push sync endpoint. */
public record SyncPushRequest(@NotNull @Valid SyncPushChanges changes) {}
