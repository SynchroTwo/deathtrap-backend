package in.deathtrap.common.types.dto;

import java.util.List;

/** Payload of client-side changes in a WatermelonDB push sync request. */
public record SyncPushChanges(List<NomineeAssignmentUpdate> nomineeAssignments) {}
