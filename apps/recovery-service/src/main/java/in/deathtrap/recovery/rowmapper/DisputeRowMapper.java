package in.deathtrap.recovery.rowmapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import org.springframework.jdbc.core.RowMapper;

/** Maps dispute_log rows. */
public class DisputeRowMapper implements RowMapper<DisputeRowMapper.Dispute> {

    public static final DisputeRowMapper INSTANCE = new DisputeRowMapper();

    private DisputeRowMapper() {}

    @Override
    public Dispute mapRow(ResultSet rs, int rowNum) throws SQLException {
        Timestamp raisedAt = rs.getTimestamp("raised_at");
        Timestamp resolvedAt = rs.getTimestamp("resolved_at");
        Timestamp createdAt = rs.getTimestamp("created_at");
        return new Dispute(
                rs.getString("dispute_id"),
                rs.getString("session_id"),
                rs.getString("raised_by"),
                rs.getString("raised_by_type"),
                rs.getString("reason"),
                rs.getString("status"),
                raisedAt != null ? raisedAt.toInstant() : Instant.EPOCH,
                rs.getString("resolved_by"),
                resolvedAt != null ? resolvedAt.toInstant() : null,
                rs.getString("resolution_notes"),
                createdAt != null ? createdAt.toInstant() : Instant.EPOCH);
    }

    /** Domain record for a dispute. */
    public record Dispute(
            String disputeId,
            String sessionId,
            String raisedBy,
            String raisedByType,
            String reason,
            String status,
            Instant raisedAt,
            String resolvedBy,
            Instant resolvedAt,
            String resolutionNotes,
            Instant createdAt
    ) {}
}
