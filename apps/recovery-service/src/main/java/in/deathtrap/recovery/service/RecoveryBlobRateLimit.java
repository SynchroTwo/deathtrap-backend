package in.deathtrap.recovery.service;

import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;

/** Enforces a per-creator rate limit on POST /recovery/blob.
 *  Counts blobs the creator has uploaded in the last hour
 *  (regardless of status — superseded blobs still count, since the
 *  cost we're rate-limiting is upload + S3 write + audit).
 *  Per docs/RECOVERY_SPEC_V1_BACKEND_CHANGES.md §4 rule 10. */
@Service
public class RecoveryBlobRateLimit {

    private static final Logger log = LoggerFactory.getLogger(RecoveryBlobRateLimit.class);
    private static final int MAX_UPLOADS_PER_HOUR = 10;

    private static final String COUNT_HOURLY_BLOBS =
            "SELECT COUNT(*) FROM recovery_blobs " +
            "WHERE creator_id = ? AND created_at > NOW() - INTERVAL '1 hour'";

    private static final RowMapper<Integer> INT_MAPPER = (rs, row) -> rs.getInt(1);

    private final DbClient dbClient;

    public RecoveryBlobRateLimit(DbClient dbClient) {
        this.dbClient = dbClient;
    }

    /** Throws AppException.rateLimited() if the creator has exceeded the hourly cap. */
    public void check(String creatorId) {
        Integer count = dbClient.queryOne(COUNT_HOURLY_BLOBS, INT_MAPPER, creatorId).orElse(0);
        if (count >= MAX_UPLOADS_PER_HOUR) {
            log.warn("Recovery blob rate limit exceeded for creatorId={} count={}",
                    creatorId, count);
            throw AppException.rateLimited();
        }
    }
}
