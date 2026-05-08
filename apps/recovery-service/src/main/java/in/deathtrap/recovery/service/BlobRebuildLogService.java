package in.deathtrap.recovery.service;

import in.deathtrap.common.crypto.CsprngUtil;
import in.deathtrap.common.db.DbClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/** Logs blob rebuild events — never throws, errors are only logged. */
@Component
public class BlobRebuildLogService {

    private static final Logger log = LoggerFactory.getLogger(BlobRebuildLogService.class);

    private static final String INSERT_REBUILD_LOG =
            "INSERT INTO blob_rebuild_log (rebuild_id, creator_id, old_blob_id, new_blob_id, " +
            "rebuild_reason, triggered_by, triggered_by_type, rebuilt_at, created_at) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())";

    private final DbClient db;

    /** Constructs BlobRebuildLogService with required DbClient. */
    public BlobRebuildLogService(DbClient db) {
        this.db = db;
    }

    /**
     * Logs a blob rebuild event.
     * Non-throwing — rebuild log failure must not block primary operation.
     */
    public void log(String creatorId, String oldBlobId, String newBlobId,
                    String rebuildReason, String triggeredById, String triggeredByType) {
        try {
            db.execute(INSERT_REBUILD_LOG,
                    CsprngUtil.randomUlid(), creatorId, oldBlobId, newBlobId,
                    rebuildReason, triggeredById, triggeredByType);
        } catch (Exception e) {
            log.error("Failed to write blob_rebuild_log: creatorId={} error={}", creatorId, e.getMessage(), e);
        }
    }
}
