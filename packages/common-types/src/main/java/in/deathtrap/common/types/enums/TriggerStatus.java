package in.deathtrap.common.types.enums;

/** Lifecycle state of a death-trigger workflow. */
public enum TriggerStatus {
    PENDING_THRESHOLD,
    THRESHOLD_MET,
    PENDING_ADMIN,
    APPROVED,
    ACTIVE,
    HALTED,
    COMPLETED,
    CANCELLED
}
