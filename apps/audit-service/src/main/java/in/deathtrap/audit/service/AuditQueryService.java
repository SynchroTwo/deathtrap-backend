package in.deathtrap.audit.service;

import in.deathtrap.audit.rowmapper.AuditLogRowMapper;
import in.deathtrap.audit.rowmapper.AuditLogRowMapper.AuditLogRow;
import in.deathtrap.common.db.DbClient;
import java.sql.Timestamp;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Service;

/** Builds and executes dynamic paginated queries against the audit_log table. */
@Service
public class AuditQueryService {

    private final DbClient db;

    /** Constructs AuditQueryService with required DbClient. */
    public AuditQueryService(DbClient db) {
        this.db = db;
    }

    /**
     * Queries audit_log with optional filters and pagination.
     * size is capped at 200. Returns total count and page of entries.
     */
    public AuditQueryResult query(String actorId, String targetId, String eventType,
                                   String fromDate, String toDate, int page, int size) {
        int effectiveSize = Math.min(size, 200);

        List<Object> filterParams = new ArrayList<>();
        StringBuilder where = new StringBuilder(" WHERE 1=1");

        if (actorId != null && !actorId.isBlank()) {
            where.append(" AND actor_id = ?");
            filterParams.add(actorId);
        }
        if (targetId != null && !targetId.isBlank()) {
            where.append(" AND target_id = ?");
            filterParams.add(targetId);
        }
        if (eventType != null && !eventType.isBlank()) {
            where.append(" AND event_type = ?");
            filterParams.add(eventType);
        }
        if (fromDate != null && !fromDate.isBlank()) {
            where.append(" AND created_at >= ?");
            filterParams.add(Timestamp.from(
                    LocalDate.parse(fromDate).atStartOfDay(ZoneOffset.UTC).toInstant()));
        }
        if (toDate != null && !toDate.isBlank()) {
            where.append(" AND created_at < ?");
            // exclusive upper bound: start of the day after toDate
            filterParams.add(Timestamp.from(
                    LocalDate.parse(toDate).plusDays(1).atStartOfDay(ZoneOffset.UTC).toInstant()));
        }

        String whereClause = where.toString();

        long total = db.queryOne(
                "SELECT COUNT(*) FROM audit_log" + whereClause,
                (rs, r) -> rs.getLong(1),
                filterParams.toArray()).orElse(0L);

        List<Object> pageParams = new ArrayList<>(filterParams);
        pageParams.add(effectiveSize);
        pageParams.add((long) page * effectiveSize);

        List<AuditLogRow> entries = db.query(
                "SELECT * FROM audit_log" + whereClause + " ORDER BY created_at DESC LIMIT ? OFFSET ?",
                AuditLogRowMapper.INSTANCE,
                pageParams.toArray());

        return new AuditQueryResult(total, entries);
    }

    /** Paginated result from an audit log query. */
    public record AuditQueryResult(long total, List<AuditLogRow> entries) {}
}
