package in.deathtrap.trigger.service;

import in.deathtrap.common.db.DbClient;
import org.springframework.stereotype.Service;

/** Provides DB operations on trigger_events shared by multiple handlers. */
@Service
public class TriggerEventService {

    private static final String HALT_PENDING_BY_CREATOR =
            "UPDATE trigger_events SET status = 'halted', updated_at = NOW() " +
            "WHERE creator_id = ? AND status IN ('pending_threshold', 'threshold_met', 'pending_admin')";

    private final DbClient db;

    /** Constructs TriggerEventService with required dependencies. */
    public TriggerEventService(DbClient db) {
        this.db = db;
    }

    /**
     * Halts any pending trigger events for the given creator.
     *
     * @return number of rows updated (0 if no pending trigger existed)
     */
    public int haltPendingTriggers(String creatorId) {
        return db.execute(HALT_PENDING_BY_CREATOR, creatorId);
    }
}
