package in.deathtrap.audit.rowmapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import org.springframework.jdbc.core.RowMapper;

/** Maps a row from audit_log to an AuditLogRow record. */
public class AuditLogRowMapper implements RowMapper<AuditLogRowMapper.AuditLogRow> {

    /** Singleton instance for reuse across services. */
    public static final AuditLogRowMapper INSTANCE = new AuditLogRowMapper();

    private AuditLogRowMapper() {}

    @Override
    public AuditLogRow mapRow(ResultSet rs, int rowNum) throws SQLException {
        Timestamp createdAt = rs.getTimestamp("created_at");
        return new AuditLogRow(
                rs.getString("audit_id"),
                rs.getString("event_type"),
                rs.getString("actor_id"),
                rs.getString("actor_type"),
                rs.getString("target_id"),
                rs.getString("target_type"),
                rs.getString("session_id"),
                rs.getString("ip_address"),
                rs.getString("result"),
                rs.getString("failure_reason"),
                rs.getString("metadata_json"),
                rs.getString("prev_hash"),
                rs.getString("entry_hash"),
                createdAt != null ? createdAt.toInstant() : Instant.now());
    }

    /** Domain record representing a single audit log entry. */
    public record AuditLogRow(
            String auditId,
            String eventType,
            String actorId,
            String actorType,
            String targetId,
            String targetType,
            String sessionId,
            String ipAddress,
            String result,
            String failureReason,
            String metadataJson,
            String prevHash,
            String entryHash,
            Instant createdAt
    ) {}
}
