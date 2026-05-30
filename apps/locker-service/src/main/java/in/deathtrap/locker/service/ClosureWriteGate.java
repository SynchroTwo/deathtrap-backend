package in.deathtrap.locker.service;

import in.deathtrap.common.db.DbClient;
import in.deathtrap.common.errors.AppException;
import in.deathtrap.common.errors.ErrorCode;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;

/** E011 Phase 1B §6 — hard write gate on locker writes when an account_closure
 *  is open or finalising/closed for the creator.
 *
 *  Returns 423 LOCKED with FAMILY_VAULT_CLOSURE_LOCKED + the closure context
 *  in error.details so the FE can render the dedicated "closure pending"
 *  surface. No caching (Phase 1A decision mirrored here) — single indexed
 *  query, ~1ms warm. */
@Service
public class ClosureWriteGate {

    private static final String SELECT_LATEST_BLOCKING_CLOSURE =
            "SELECT closure_id, status::text AS status, objection_window_ends_at " +
            "FROM account_closure WHERE creator_id = ? " +
            "AND status IN ('pending_objection', 'finalising', 'closed') " +
            "ORDER BY triggered_at DESC LIMIT 1";

    private static final RowMapper<BlockingClosure> MAPPER = (rs, row) -> new BlockingClosure(
            rs.getString("closure_id"),
            rs.getString("status"),
            Optional.ofNullable(rs.getTimestamp("objection_window_ends_at"))
                    .map(Timestamp::toInstant).orElse(null));

    private final DbClient dbClient;

    public ClosureWriteGate(DbClient dbClient) {
        this.dbClient = dbClient;
    }

    /** Throws 423 LOCKED if the creator has an open or finalising/closed closure.
     *  Call this at the top of every locker-service write handler. */
    public void assertWritesAllowed(String creatorId) {
        Optional<BlockingClosure> rowOpt = dbClient.queryOne(SELECT_LATEST_BLOCKING_CLOSURE, MAPPER, creatorId);
        if (rowOpt.isEmpty()) {
            return;
        }
        BlockingClosure closure = rowOpt.get();
        Map<String, Object> details;
        if ("pending_objection".equals(closure.status) && closure.objectionWindowEndsAt != null) {
            details = Map.of(
                    "closureId", closure.closureId,
                    "closureStatus", closure.status,
                    "objectionWindowEndsAt", closure.objectionWindowEndsAt.toString());
        } else {
            details = Map.of(
                    "closureId", closure.closureId,
                    "closureStatus", closure.status);
        }
        throw new AppException(ErrorCode.FAMILY_VAULT_CLOSURE_LOCKED, details);
    }

    private record BlockingClosure(String closureId, String status, Instant objectionWindowEndsAt) {}
}
